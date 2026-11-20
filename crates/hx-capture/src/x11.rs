//! X11 backend: XDamage for change detection, MIT-SHM for copy-free reads, XFixes for the
//! cursor, XInput2 raw motion for pointer movement, RandR for resizing.

use crate::clock::mono_ns;
use crate::cursor::{CursorEvent, CursorPosition, CursorShape};
use crate::error::CaptureError;
use crate::frame::{Frame, SlotBuf};
use crate::geometry::{Rect, Size};
use crate::shm::{Memory, ShmMap};
use crate::{Capture, Wake};
use crossbeam_channel::{Receiver, Sender, bounded};
use rustix::event::{PollFd, PollFlags, poll};
use rustix::io::Errno;
use rustix::time::Timespec;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use x11rb::connection::{Connection, RequestConnection};
use x11rb::errors::ReplyError;
use x11rb::protocol::Event;
use x11rb::protocol::damage::{self, ConnectionExt as _};
use x11rb::protocol::randr::{
    self, ConnectionExt as _, ModeFlag, NotifyMask as RandrNotifyMask, Rotation,
};
use x11rb::protocol::shm::{self, ConnectionExt as _};
use x11rb::protocol::xfixes::{self, ConnectionExt as _, CursorNotifyMask};
use x11rb::protocol::xinput::{self, ConnectionExt as _, XIEventMask};
use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat, ImageOrder, Screen, Setup, Window};
use x11rb::rust_connection::RustConnection;
use x11rb::x11_utils::X11Error;
use x11rb::{CURRENT_TIME, NONE};

/// `XIAllMasterDevices`.
const XI_ALL_MASTER_DEVICES: u16 = 1;
/// Pointer polling interval when XInput2 raw motion is unavailable.
const POINTER_FALLBACK_POLL: Duration = Duration::from_millis(33);
/// Most queued cursor events kept; the oldest are dropped beyond this.
const MAX_CURSOR_EVENTS: usize = 512;

/// Settings for [`X11Capture::connect`].
#[derive(Clone, Debug)]
pub struct X11Config {
    /// Display name such as `:0`; `None` uses `$DISPLAY`.
    pub display: Option<String>,
    /// Frame buffers in the pool (frames in flight before `grab` reports no free buffer).
    pub buffers: usize,
    /// Track the cursor (shape and position events).
    pub cursor: bool,
    /// Minimum time between pointer position reads (caps the position event rate).
    pub pointer_interval: Duration,
    /// More damage rectangles than this collapse into the full frame.
    pub max_damage_rects: usize,
}

impl Default for X11Config {
    fn default() -> Self {
        Self {
            display: None,
            buffers: 4,
            cursor: true,
            pointer_interval: Duration::from_millis(8),
            max_damage_rects: 32,
        }
    }
}

struct Pool {
    rx: Receiver<SlotBuf>,
    tx: Sender<SlotBuf>,
    count: usize,
}

/// A replaced pool whose frames are still out; its X segments are detached when they return.
struct Retired {
    rx: Receiver<SlotBuf>,
    outstanding: usize,
}

/// Screen capture from an X11 display.
pub struct X11Capture {
    conn: RustConnection,
    root: Window,
    size: Size,
    damage: damage::Damage,
    region: xfixes::Region,
    cfg: X11Config,
    use_shm: bool,
    xi2: bool,
    randr: bool,
    pool: Pool,
    retired: Vec<Retired>,
    seq: u64,
    pending_since: Option<u64>,
    force: bool,
    // Things seen since the last `wait` returned.
    new_damage: bool,
    new_cursor: bool,
    resized: Option<Size>,
    // Cursor state.
    cursor_dirty: bool,
    pointer_dirty: bool,
    last_pointer_ns: u64,
    last_pos: Option<(i16, i16)>,
    shape: Option<Arc<CursorShape>>,
    events: VecDeque<CursorEvent>,
}

impl X11Capture {
    /// Connect, verify the display's pixel format and extensions, and allocate the buffer pool.
    pub fn connect(cfg: &X11Config) -> Result<Self, CaptureError> {
        let (conn, screen_num) = RustConnection::connect(cfg.display.as_deref())?;
        let setup = conn.setup();
        let screen = setup.roots.get(screen_num).ok_or_else(|| {
            CaptureError::UnsupportedFormat(format!("screen {screen_num} does not exist"))
        })?;
        check_format(setup, screen)?;
        let root = screen.root;
        let size = Size::new(
            u32::from(screen.width_in_pixels),
            u32::from(screen.height_in_pixels),
        );

        require(&conn, damage::X11_EXTENSION_NAME, "DAMAGE", "1.1")?;
        require(&conn, xfixes::X11_EXTENSION_NAME, "XFIXES", "4.0")?;
        conn.damage_query_version(1, 1)?.reply()?;
        conn.xfixes_query_version(4, 0)?.reply()?;

        let use_shm = match conn.extension_information(shm::X11_EXTENSION_NAME)? {
            Some(_) => {
                let v = conn.shm_query_version()?.reply()?;
                (v.major_version, v.minor_version) >= (1, 2)
            }
            None => false,
        };
        let randr = match conn.extension_information(randr::X11_EXTENSION_NAME)? {
            Some(_) => {
                let v = conn.randr_query_version(1, 5)?.reply()?;
                if (v.major_version, v.minor_version) >= (1, 2) {
                    conn.randr_select_input(root, RandrNotifyMask::SCREEN_CHANGE)?
                        .check()?;
                    true
                } else {
                    false
                }
            }
            None => false,
        };
        let xi2 = cfg.cursor && select_raw_motion(&conn, root)?;

        let damage = conn.generate_id().map_err(CaptureError::from_reply_or_id)?;
        let region = conn.generate_id().map_err(CaptureError::from_reply_or_id)?;
        conn.damage_create(damage, root, damage::ReportLevel::NON_EMPTY)?
            .check()?;
        conn.xfixes_create_region(region, &[])?.check()?;
        // Damage that predates this connection is not news: a new client forces a full frame.
        conn.damage_subtract(damage, NONE, NONE)?.check()?;
        if cfg.cursor {
            conn.xfixes_select_cursor_input(root, CursorNotifyMask::DISPLAY_CURSOR)?
                .check()?;
        }
        conn.flush()?;

        // Placeholder pool, replaced right below once `use_shm` is settled by a real attach.
        let (tx, rx) = bounded(1);
        let mut me = Self {
            conn,
            root,
            size,
            damage,
            region,
            cfg: cfg.clone(),
            use_shm,
            xi2,
            randr,
            pool: Pool { rx, tx, count: 0 },
            retired: Vec::new(),
            seq: 0,
            pending_since: None,
            force: false,
            new_damage: false,
            new_cursor: false,
            resized: None,
            cursor_dirty: cfg.cursor,
            pointer_dirty: cfg.cursor,
            last_pointer_ns: 0,
            last_pos: None,
            shape: None,
            events: VecDeque::new(),
        };
        me.pool = me.make_pool(size)?;
        // Round-trip so the notification for the pre-existing damage (already cleared above)
        // is in the queue, then drop it: only changes after this point count.
        me.conn.get_input_focus()?.reply()?;
        me.pump()?;
        me.pending_since = None;
        me.new_damage = false;
        Ok(me)
    }

    /// True when buffers are shared with the X server (copy-free); false on the plain
    /// `GetImage` fallback.
    pub fn uses_shared_memory(&self) -> bool {
        self.use_shm
    }

    /// True when pointer movement arrives as events rather than being polled.
    pub fn pointer_events(&self) -> bool {
        self.xi2
    }

    fn make_pool(&mut self, size: Size) -> Result<Pool, CaptureError> {
        let n = self.cfg.buffers.max(2);
        let stride = size.width as usize * 4;
        let len = stride * size.height as usize;
        let (tx, rx) = bounded(n);
        for _ in 0..n {
            let slot = self.make_slot(size, len)?;
            tx.send(slot).map_err(|_| {
                CaptureError::SharedMemory(std::io::Error::other("buffer pool closed"))
            })?;
        }
        Ok(Pool { rx, tx, count: n })
    }

    fn make_slot(&mut self, size: Size, len: usize) -> Result<SlotBuf, CaptureError> {
        if self.use_shm {
            let (map, fd) = ShmMap::create(len)?;
            let seg = self
                .conn
                .generate_id()
                .map_err(CaptureError::from_reply_or_id)?;
            match self.conn.shm_attach_fd(seg, fd, false)?.check() {
                Ok(()) => {
                    return Ok(SlotBuf {
                        mem: Memory::Shm(map),
                        seg: Some(seg),
                        damage: Vec::with_capacity(self.cfg.max_damage_rects.max(1)),
                        size,
                    });
                }
                // The server refuses descriptor passing (for example a remote or sandboxed
                // X server): fall back to plain GetImage for the rest of the session.
                Err(ReplyError::X11Error(_)) => self.use_shm = false,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(SlotBuf {
            mem: Memory::Heap(Vec::new()),
            seg: None,
            damage: Vec::with_capacity(self.cfg.max_damage_rects.max(1)),
            size,
        })
    }

    fn detach(&self, slot: &SlotBuf) {
        if let Some(seg) = slot.seg {
            // A failed detach only leaks a segment until the connection closes.
            let _ = self.conn.shm_detach(seg);
        }
    }

    fn reap_retired(&mut self) {
        let mut retired = std::mem::take(&mut self.retired);
        retired.retain_mut(|r| {
            while let Ok(slot) = r.rx.try_recv() {
                self.detach(&slot);
                r.outstanding -= 1;
            }
            r.outstanding > 0
        });
        self.retired = retired;
    }

    /// Read the root geometry and, if it changed, replace the buffer pool.
    fn refresh_size(&mut self) -> Result<(), CaptureError> {
        let g = self.conn.get_geometry(self.root)?.reply()?;
        let new = Size::new(u32::from(g.width), u32::from(g.height));
        if new == self.size || new.width == 0 || new.height == 0 {
            return Ok(());
        }
        let pool = self.make_pool(new)?;
        let old = std::mem::replace(&mut self.pool, pool);
        let mut outstanding = old.count;
        while let Ok(slot) = old.rx.try_recv() {
            self.detach(&slot);
            outstanding -= 1;
        }
        if outstanding > 0 {
            self.retired.push(Retired {
                rx: old.rx,
                outstanding,
            });
        }
        self.size = new;
        self.resized = Some(new);
        self.force = true;
        self.pending_since.get_or_insert_with(mono_ns);
        Ok(())
    }

    fn push_event(&mut self, ev: CursorEvent) {
        if let (CursorEvent::Position(_), Some(CursorEvent::Position(_))) =
            (&ev, self.events.back())
        {
            self.events.pop_back();
        }
        if self.events.len() >= MAX_CURSOR_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(ev);
        self.new_cursor = true;
    }

    fn fetch_cursor_shape(&mut self, force: bool) -> Result<(), CaptureError> {
        let r = self.conn.xfixes_get_cursor_image()?.reply()?;
        let shape = CursorShape::new(r.width, r.height, r.xhot, r.yhot, r.cursor_image);
        if !force && self.shape.as_ref().is_some_and(|s| s.id == shape.id) {
            return Ok(());
        }
        let shape = Arc::new(shape);
        self.shape = Some(shape.clone());
        self.push_event(CursorEvent::Shape(shape));
        Ok(())
    }

    fn service_cursor(&mut self) -> Result<(), CaptureError> {
        if !self.cfg.cursor {
            return Ok(());
        }
        if self.cursor_dirty {
            self.cursor_dirty = false;
            self.fetch_cursor_shape(false)?;
        }
        if self.pointer_dirty {
            let now = mono_ns();
            let min = self.cfg.pointer_interval.as_nanos() as u64;
            if now.saturating_sub(self.last_pointer_ns) >= min {
                self.pointer_dirty = false;
                self.last_pointer_ns = now;
                let p = self.conn.query_pointer(self.root)?.reply()?;
                let pos = (p.root_x, p.root_y);
                if self.last_pos != Some(pos) {
                    self.last_pos = Some(pos);
                    self.push_event(CursorEvent::Position(CursorPosition {
                        x: pos.0,
                        y: pos.1,
                        t_ns: now,
                    }));
                }
            }
        }
        Ok(())
    }

    /// Process every event the server has sent.
    fn pump(&mut self) -> Result<(), CaptureError> {
        let mut check_size = false;
        while let Some(ev) = self.conn.poll_for_event()? {
            match ev {
                Event::DamageNotify(_) => {
                    self.pending_since.get_or_insert_with(mono_ns);
                    self.new_damage = true;
                }
                Event::XfixesCursorNotify(_) => self.cursor_dirty = true,
                Event::XinputRawMotion(_) => self.pointer_dirty = true,
                Event::RandrScreenChangeNotify(_) => check_size = true,
                Event::Error(e) => return Err(CaptureError::X11(e)),
                _ => {}
            }
        }
        if check_size {
            self.refresh_size()?;
        }
        self.service_cursor()
    }

    fn has_unreported(&self) -> bool {
        self.new_damage || self.new_cursor || self.resized.is_some()
    }

    /// Sleep until the connection is readable or `timeout` passes.
    fn block(&self, timeout: Option<Duration>) -> Result<(), CaptureError> {
        self.conn.flush()?;
        let ts = timeout.map(|d| Timespec {
            tv_sec: d.as_secs().min(i64::MAX as u64) as i64,
            tv_nsec: i64::from(d.subsec_nanos()),
        });
        let mut fds = [PollFd::new(self.conn.stream(), PollFlags::IN)];
        match poll(&mut fds, ts.as_ref()) {
            Ok(_) | Err(Errno::INTR) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn randr_resize(&mut self, size: Size) -> Result<(), CaptureError> {
        if !self.randr {
            return Err(CaptureError::MissingExtension("RANDR", "1.2"));
        }
        let (root, conn) = (self.root, &self.conn);
        let range = conn.randr_get_screen_size_range(root)?.reply()?;
        let (w, h) = (
            u16::try_from(size.width).unwrap_or(u16::MAX),
            u16::try_from(size.height).unwrap_or(u16::MAX),
        );
        if w < range.min_width || h < range.min_height {
            return Err(CaptureError::InvalidSize {
                width: size.width,
                height: size.height,
                reason: "below the minimum screen size",
            });
        }
        if w > range.max_width || h > range.max_height {
            return Err(CaptureError::InvalidSize {
                width: size.width,
                height: size.height,
                reason: "above the maximum screen size",
            });
        }
        if size == self.size {
            return Ok(());
        }

        let res = conn.randr_get_screen_resources_current(root)?.reply()?;
        // The first connected output, preferring one that is already driven by a CRTC.
        let mut chosen: Option<(randr::Output, randr::GetOutputInfoReply)> = None;
        for &output in &res.outputs {
            let info = conn
                .randr_get_output_info(output, res.config_timestamp)?
                .reply()?;
            if info.connection != randr::Connection::CONNECTED {
                continue;
            }
            let better = chosen
                .as_ref()
                .is_none_or(|(_, c)| c.crtc == NONE && info.crtc != NONE);
            if better {
                chosen = Some((output, info));
            }
        }
        let (output, info) =
            chosen.ok_or_else(|| CaptureError::Resize("no connected output".to_string()))?;
        let crtc = if info.crtc != NONE {
            info.crtc
        } else {
            *info
                .crtcs
                .first()
                .ok_or_else(|| CaptureError::Resize("output has no usable CRTC".to_string()))?
        };

        // Reuse a mode of exactly this size when the output offers one, or the server knows
        // one (attach it); otherwise create it. Dummy and virtual drivers have no EDID modes,
        // so creating one is the normal path there.
        let matches = |m: &randr::ModeInfo| {
            u32::from(m.width) == size.width && u32::from(m.height) == size.height
        };
        let mode = if let Some(m) = res
            .modes
            .iter()
            .find(|m| matches(m) && info.modes.contains(&m.id))
        {
            m.id
        } else {
            let mode = if let Some(m) = res.modes.iter().find(|m| matches(m)) {
                m.id
            } else {
                let name = format!("hx-{}x{}", size.width, size.height);
                conn.randr_create_mode(
                    root,
                    reduced_blanking_mode(w, h, name.len()),
                    name.as_bytes(),
                )?
                .reply()?
                .mode
            };
            conn.randr_add_output_mode(output, mode)?.check()?;
            mode
        };

        // Turn the CRTC off so the screen may shrink, resize, then bring it back.
        let set = |mode, outputs: &[randr::Output]| -> Result<(), CaptureError> {
            let res = conn.randr_get_screen_resources_current(root)?.reply()?;
            let r = conn
                .randr_set_crtc_config(
                    crtc,
                    CURRENT_TIME,
                    res.config_timestamp,
                    0,
                    0,
                    mode,
                    Rotation::ROTATE0,
                    outputs,
                )?
                .reply()?;
            if r.status == randr::SetConfig::SUCCESS {
                Ok(())
            } else {
                Err(CaptureError::Resize(format!(
                    "SetCrtcConfig status {:?}",
                    r.status
                )))
            }
        };
        set(NONE, &[])?;
        // 96 dpi.
        let mm = |px: u32| (px * 254 + 480) / 960;
        conn.randr_set_screen_size(root, w, h, mm(size.width), mm(size.height))?
            .check()?;
        set(mode, &[output])?;
        conn.flush()?;
        self.refresh_size()
    }
}

impl Capture for X11Capture {
    fn size(&self) -> Size {
        self.size
    }

    fn wait(&mut self, timeout: Option<Duration>) -> Result<Wake, CaptureError> {
        self.pump()?;
        if !self.has_unreported() {
            let mut t = timeout;
            let mut cap = |limit: Duration| t = Some(t.map_or(limit, |c| c.min(limit)));
            if self.cfg.cursor {
                if self.pointer_dirty {
                    // A position read is waiting on the rate cap.
                    let min = self.cfg.pointer_interval.as_nanos() as u64;
                    let since = mono_ns().saturating_sub(self.last_pointer_ns);
                    cap(Duration::from_nanos(min.saturating_sub(since)));
                }
                if !self.xi2 {
                    cap(POINTER_FALLBACK_POLL);
                }
            }
            self.block(t)?;
            if self.cfg.cursor && !self.xi2 {
                self.pointer_dirty = true;
            }
            self.pump()?;
        }
        let wake = Wake {
            damage: std::mem::take(&mut self.new_damage),
            cursor: std::mem::take(&mut self.new_cursor),
            resized: self.resized.take(),
        };
        Ok(wake)
    }

    fn damage_pending(&self) -> bool {
        self.pending_since.is_some() || self.force
    }

    fn damage_since_ns(&self) -> Option<u64> {
        self.pending_since
    }

    fn force_full_frame(&mut self) {
        self.force = true;
        self.pending_since.get_or_insert_with(mono_ns);
    }

    fn grab(&mut self, buffer_wait: Duration) -> Result<Option<Frame>, CaptureError> {
        self.pump()?;
        if !self.damage_pending() {
            return Ok(None);
        }
        self.reap_retired();
        let Ok(mut slot) = self.pool.rx.recv_timeout(buffer_wait) else {
            return Ok(None);
        };
        let size = self.size;
        let stride = size.width as usize * 4;
        let len = stride * size.height as usize;
        let t_damage = self.pending_since.unwrap_or_else(mono_ns);
        let full = self.force;
        let (w, h) = (size.width as u16, size.height as u16);

        // Take the accumulated damage first, then the image: damage that lands in between
        // is both in the image and re-reported, which costs at most one extra frame.
        let sent = (|| -> Result<_, CaptureError> {
            self.conn.damage_subtract(self.damage, NONE, self.region)?;
            let rects = self.conn.xfixes_fetch_region(self.region)?;
            let image = if let (true, Some(seg)) = (self.use_shm, slot.seg) {
                let c = self.conn.shm_get_image(
                    self.root,
                    0,
                    0,
                    w,
                    h,
                    !0,
                    ImageFormat::Z_PIXMAP.into(),
                    seg,
                    0,
                )?;
                Image::Shm(c.reply())
            } else {
                let c = self
                    .conn
                    .get_image(ImageFormat::Z_PIXMAP, self.root, 0, 0, w, h, !0)?;
                Image::Plain(c.reply())
            };
            let rects = rects.reply().map(|r| r.rectangles).unwrap_or_default();
            Ok((rects, image))
        })();
        let (rects, image) = match sent {
            Ok(v) => v,
            Err(e) => {
                let _ = self.pool.tx.send(slot);
                return Err(e);
            }
        };

        let outcome: Result<(), ReplyError> = match image {
            Image::Shm(Ok(r)) if r.size as usize >= len => Ok(()),
            Image::Shm(Ok(_)) => Err(ReplyError::X11Error(short_image_error())),
            Image::Shm(Err(e)) => Err(e),
            Image::Plain(Ok(r)) if r.data.len() >= len => {
                slot.mem = Memory::Heap(r.data);
                Ok(())
            }
            Image::Plain(Ok(_)) => Err(ReplyError::X11Error(short_image_error())),
            Image::Plain(Err(e)) => Err(e),
        };
        if let Err(e) = outcome {
            let _ = self.pool.tx.send(slot);
            // The screen was probably resized under us: pick up the new size and let the
            // caller try again (damage stays pending). Anything else is a real error.
            return match e {
                ReplyError::X11Error(ref x) if is_stale_geometry(x) => {
                    self.refresh_size()?;
                    Ok(None)
                }
                e => Err(e.into()),
            };
        }
        let t_capture = mono_ns();

        slot.damage.clear();
        let full_rect = Rect::full(size);
        let reported = rects;
        if full || reported.is_empty() || reported.len() > self.cfg.max_damage_rects {
            slot.damage.push(full_rect);
        } else {
            for r in &reported {
                let rect = Rect::new(
                    i32::from(r.x),
                    i32::from(r.y),
                    u32::from(r.width),
                    u32::from(r.height),
                )
                .clip(size);
                if !rect.is_empty() {
                    slot.damage.push(rect);
                }
            }
            if slot.damage.is_empty() {
                slot.damage.push(full_rect);
            }
        }
        debug_assert_eq!(slot.size, size);

        self.force = false;
        self.pending_since = None;
        let seq = self.seq;
        self.seq += 1;
        Ok(Some(Frame {
            seq,
            size,
            stride,
            t_damage_ns: t_damage,
            t_capture_ns: t_capture,
            buf: Some(slot),
            ret: self.pool.tx.clone(),
        }))
    }

    fn request_resize(&mut self, size: Size) -> Result<(), CaptureError> {
        self.randr_resize(size)
    }

    fn drain_cursor(&mut self, sink: &mut dyn FnMut(CursorEvent)) {
        while let Some(ev) = self.events.pop_front() {
            sink(ev);
        }
    }

    fn refresh_cursor(&mut self) -> Result<(), CaptureError> {
        if self.cfg.cursor {
            self.fetch_cursor_shape(true)?;
            self.last_pos = None;
            self.pointer_dirty = true;
            self.service_cursor()?;
        }
        Ok(())
    }
}

enum Image {
    Shm(Result<shm::GetImageReply, ReplyError>),
    Plain(Result<x11rb::protocol::xproto::GetImageReply, ReplyError>),
}

fn is_stale_geometry(e: &X11Error) -> bool {
    use x11rb::protocol::ErrorKind;
    matches!(e.error_kind, ErrorKind::Match | ErrorKind::Value)
}

/// Synthesised error for an image reply smaller than the request.
fn short_image_error() -> X11Error {
    X11Error {
        error_kind: x11rb::protocol::ErrorKind::Match,
        error_code: 8,
        sequence: 0,
        bad_value: 0,
        minor_opcode: 0,
        major_opcode: 0,
        extension_name: None,
        request_name: None,
    }
}

fn require(
    conn: &RustConnection,
    name: &'static str,
    short: &'static str,
    version: &'static str,
) -> Result<(), CaptureError> {
    match conn.extension_information(name)? {
        Some(_) => Ok(()),
        None => Err(CaptureError::MissingExtension(short, version)),
    }
}

/// Subscribe to XInput2 raw motion on the root window. Returns false if the server has no
/// XInput 2, in which case the pointer is polled instead.
fn select_raw_motion(conn: &RustConnection, root: Window) -> Result<bool, CaptureError> {
    if conn
        .extension_information(xinput::X11_EXTENSION_NAME)?
        .is_none()
    {
        return Ok(false);
    }
    let v = conn.xinput_xi_query_version(2, 0)?.reply()?;
    if v.major_version < 2 {
        return Ok(false);
    }
    let mask = xinput::EventMask {
        deviceid: XI_ALL_MASTER_DEVICES,
        mask: vec![XIEventMask::RAW_MOTION],
    };
    conn.xinput_xi_select_events(root, &[mask])?.check()?;
    Ok(true)
}

/// Capture needs 32 bits per pixel, little-endian, with the usual BGRX channel masks.
fn check_format(setup: &Setup, screen: &Screen) -> Result<(), CaptureError> {
    let bad = |what: String| Err(CaptureError::UnsupportedFormat(what));
    let fmt = setup
        .pixmap_formats
        .iter()
        .find(|f| f.depth == screen.root_depth);
    match fmt {
        Some(f) if f.bits_per_pixel == 32 && f.scanline_pad <= 32 => {}
        Some(f) => {
            return bad(format!(
                "depth {} uses {} bits per pixel with {}-bit padding",
                screen.root_depth, f.bits_per_pixel, f.scanline_pad
            ));
        }
        None => return bad(format!("no pixmap format for depth {}", screen.root_depth)),
    }
    if setup.image_byte_order != ImageOrder::LSB_FIRST {
        return bad("big-endian image byte order".to_string());
    }
    let visual = screen
        .allowed_depths
        .iter()
        .flat_map(|d| d.visuals.iter())
        .find(|v| v.visual_id == screen.root_visual);
    match visual {
        Some(v) if (v.red_mask, v.green_mask, v.blue_mask) == (0xff_0000, 0xff00, 0xff) => Ok(()),
        Some(v) => bad(format!(
            "channel masks {:#x}/{:#x}/{:#x}",
            v.red_mask, v.green_mask, v.blue_mask
        )),
        None => bad("root visual not found".to_string()),
    }
}

/// A CVT reduced-blanking style mode at 60 Hz.
fn reduced_blanking_mode(width: u16, height: u16, name_len: usize) -> randr::ModeInfo {
    let (w, h) = (u32::from(width), u32::from(height));
    let htotal = w + 160;
    let vtotal = h + 14;
    randr::ModeInfo {
        id: 0,
        width,
        height,
        dot_clock: htotal * vtotal * 60,
        hsync_start: width.saturating_add(48),
        hsync_end: width.saturating_add(80),
        htotal: htotal.min(u32::from(u16::MAX)) as u16,
        hskew: 0,
        vsync_start: height.saturating_add(3),
        vsync_end: height.saturating_add(8),
        vtotal: vtotal.min(u32::from(u16::MAX)) as u16,
        name_len: name_len as u16,
        mode_flags: ModeFlag::HSYNC_POSITIVE | ModeFlag::VSYNC_NEGATIVE,
    }
}
