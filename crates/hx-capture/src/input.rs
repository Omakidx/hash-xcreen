//! Input injection through the XTest extension.
//!
//! Protocol-independent: the session turns wire events into calls on [`InputInjector`].
//! Everything here assumes the caller's data is untrusted and is bounded accordingly.
//!
//! * **Keys are physical.** A HID usage is mapped to an evdev code and then to the X keycode
//!   (`code + 8`), so the server's own layout decides what character comes out and the
//!   client's layout does not matter.
//! * **Held state is tracked.** A repeated press of a held key and a release of a key that
//!   is not held are ignored (the X server auto-repeats by itself). [`InputInjector::release_all`]
//!   releases every key and button this injector holds; it runs on focus loss, when the
//!   client disconnects, and when the injector is dropped, so a vanished client cannot leave
//!   a modifier stuck.
//! * **Pointer coordinates are clamped** to the screen (protocol 13: the injector clamps).
//!   The screen size follows RandR changes.
//! * **Scrolling accumulates.** Scroll arrives in 1/120 notch units; whole notches become
//!   wheel button clicks and the remainder waits for the next event. Reversing direction
//!   drops the old remainder. At most [`MAX_SCROLL_CLICKS`] clicks per call.

use crate::{CaptureError, Size, hid};
use std::collections::BTreeSet;
use thiserror::Error;
use x11rb::connection::{Connection, RequestConnection};
use x11rb::errors::ConnectionError;
use x11rb::protocol::Event;
use x11rb::protocol::randr::{self, ConnectionExt as _, NotifyMask};
use x11rb::protocol::xproto::{
    BUTTON_PRESS_EVENT, BUTTON_RELEASE_EVENT, ConnectionExt as _, KEY_PRESS_EVENT,
    KEY_RELEASE_EVENT, MOTION_NOTIFY_EVENT, Window,
};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

/// Wheel clicks one scroll call may produce. Anything beyond is dropped.
pub const MAX_SCROLL_CLICKS: i32 = 16;
/// Largest relative motion accepted per event, in pixels per axis.
pub const MAX_RELATIVE_STEP: i32 = 4096;

const NO_TIME: u32 = 0; // CurrentTime
const WHEEL_UNIT: i32 = 120;

/// Why an input event was not injected.
#[derive(Debug, Error)]
pub enum InputError {
    #[error("the display connection failed: {0}")]
    Connection(#[from] ConnectionError),
    #[error("cannot set up input injection: {0}")]
    Setup(#[from] CaptureError),
    #[error("keyboard usage {0:#x} is not a key on this keyboard")]
    UnmappedKey(u32),
    #[error("the display has no keycode {0} for this key")]
    NoKeycode(u8),
}

impl InputError {
    /// True when the display connection is gone.
    pub fn is_fatal(&self) -> bool {
        matches!(self, InputError::Connection(_))
            || matches!(self, InputError::Setup(e) if e.is_fatal())
    }
}

/// A mouse button.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Button {
    Left,
    Middle,
    Right,
    Back,
    Forward,
}

impl Button {
    /// The X core button number.
    fn x11(self) -> u8 {
        match self {
            Button::Left => 1,
            Button::Middle => 2,
            Button::Right => 3,
            Button::Back => 8,
            Button::Forward => 9,
        }
    }
}

/// What the session needs from an input backend.
pub trait InputInjector: Send {
    /// A physical key by HID usage (keyboard page, `0..=0xE7`).
    fn key(&mut self, usage: u32, pressed: bool) -> Result<(), InputError>;
    /// A button press or release, optionally preceded by a move to `at` (remote pixels).
    fn button(
        &mut self,
        button: Button,
        pressed: bool,
        at: Option<(i32, i32)>,
    ) -> Result<(), InputError>;
    /// Move the pointer to an absolute position, clamped to the screen.
    fn move_to(&mut self, x: i32, y: i32) -> Result<(), InputError>;
    /// Move the pointer by a delta, clamped to a sane step and to the screen.
    fn move_by(&mut self, dx: i32, dy: i32) -> Result<(), InputError>;
    /// Scroll by 1/120 notch units: positive `dy` up, positive `dx` right.
    fn scroll(&mut self, dx: i32, dy: i32) -> Result<(), InputError>;
    /// Release every key and button this injector holds.
    fn release_all(&mut self) -> Result<(), InputError>;
}

/// XTest injector for an X display.
pub struct X11Input {
    conn: RustConnection,
    root: Window,
    size: Size,
    min_keycode: u8,
    max_keycode: u8,
    keys: BTreeSet<u8>,
    buttons: BTreeSet<Button>,
    /// Scroll remainders in 1/120 units.
    acc_x: i32,
    acc_y: i32,
}

impl X11Input {
    /// Connect to `display` (else `$DISPLAY`) and check for XTest.
    pub fn connect(display: Option<&str>) -> Result<Self, InputError> {
        let (conn, num) = RustConnection::connect(display).map_err(CaptureError::from)?;
        let setup = conn.setup();
        let screen = setup.roots.get(num).ok_or_else(|| {
            CaptureError::UnsupportedFormat(format!("screen {num} does not exist"))
        })?;
        let (root, min_keycode, max_keycode) = (screen.root, setup.min_keycode, setup.max_keycode);
        let size = Size::new(
            u32::from(screen.width_in_pixels),
            u32::from(screen.height_in_pixels),
        );
        if conn
            .extension_information(x11rb::protocol::xtest::X11_EXTENSION_NAME)?
            .is_none()
        {
            return Err(CaptureError::MissingExtension("XTEST", "2.1").into());
        }
        conn.xtest_get_version(2, 1)?
            .reply()
            .map_err(CaptureError::from)?;
        if conn
            .extension_information(randr::X11_EXTENSION_NAME)?
            .is_some()
        {
            // Follow screen resizes so clamping uses the current size.
            conn.randr_query_version(1, 2)?
                .reply()
                .map_err(CaptureError::from)?;
            conn.randr_select_input(root, NotifyMask::SCREEN_CHANGE)?;
        }
        conn.flush()?;
        Ok(Self {
            conn,
            root,
            size,
            min_keycode,
            max_keycode,
            keys: BTreeSet::new(),
            buttons: BTreeSet::new(),
            acc_x: 0,
            acc_y: 0,
        })
    }

    /// The screen size used for clamping.
    pub fn screen_size(&self) -> Size {
        self.size
    }

    /// Tell the injector the screen size (normally learned from RandR on its own).
    pub fn set_screen_size(&mut self, size: Size) {
        self.size = size;
    }

    /// Keys and buttons currently held by this injector.
    pub fn held(&self) -> (usize, usize) {
        (self.keys.len(), self.buttons.len())
    }

    /// Pick up screen size changes announced since the last call.
    fn drain_events(&mut self) -> Result<(), InputError> {
        while let Some(ev) = self.conn.poll_for_event()? {
            if let Event::RandrScreenChangeNotify(e) = ev {
                // The event carries the size in the screen's current rotation.
                self.size = Size::new(u32::from(e.width), u32::from(e.height));
            }
        }
        Ok(())
    }

    fn fake(&self, kind: u8, detail: u8, x: i16, y: i16) -> Result<(), InputError> {
        self.conn
            .xtest_fake_input(kind, detail, NO_TIME, self.root, x, y, 0)?;
        Ok(())
    }

    fn clamp(&self, x: i32, y: i32) -> (i16, i16) {
        let max_x = self.size.width.saturating_sub(1).min(i16::MAX as u32) as i32;
        let max_y = self.size.height.saturating_sub(1).min(i16::MAX as u32) as i32;
        (x.clamp(0, max_x) as i16, y.clamp(0, max_y) as i16)
    }

    fn do_move_to(&self, x: i32, y: i32) -> Result<(), InputError> {
        let (x, y) = self.clamp(x, y);
        self.fake(MOTION_NOTIFY_EVENT, 0, x, y)
    }

    fn wheel_click(&self, button: u8) -> Result<(), InputError> {
        self.fake(BUTTON_PRESS_EVENT, button, 0, 0)?;
        self.fake(BUTTON_RELEASE_EVENT, button, 0, 0)
    }

    fn keycode(&self, usage: u32) -> Result<u8, InputError> {
        let code = u8::try_from(usage)
            .ok()
            .filter(|u| *u <= hid::MAX_USAGE)
            .and_then(hid::hid_to_evdev)
            .ok_or(InputError::UnmappedKey(usage))?;
        let kc = hid::evdev_to_x11(code);
        if !(self.min_keycode..=self.max_keycode).contains(&kc) {
            return Err(InputError::NoKeycode(kc));
        }
        Ok(kc)
    }
}

/// Take whole notches out of `acc`; returns the signed click count (positive up/right).
fn take_clicks(acc: &mut i32, delta: i32) -> i32 {
    // Reversing direction forgets the unfinished notch of the old direction.
    if delta != 0 && *acc != 0 && (delta < 0) != (*acc < 0) {
        *acc = 0;
    }
    *acc = acc.saturating_add(delta);
    let clicks = *acc / WHEEL_UNIT;
    *acc %= WHEEL_UNIT;
    clicks.clamp(-MAX_SCROLL_CLICKS, MAX_SCROLL_CLICKS)
}

impl InputInjector for X11Input {
    fn key(&mut self, usage: u32, pressed: bool) -> Result<(), InputError> {
        let kc = self.keycode(usage)?;
        if pressed {
            if !self.keys.insert(kc) {
                return Ok(()); // already held: the server repeats on its own
            }
            self.fake(KEY_PRESS_EVENT, kc, 0, 0)?;
        } else {
            if !self.keys.remove(&kc) {
                return Ok(());
            }
            self.fake(KEY_RELEASE_EVENT, kc, 0, 0)?;
        }
        self.conn.flush()?;
        Ok(())
    }

    fn button(
        &mut self,
        button: Button,
        pressed: bool,
        at: Option<(i32, i32)>,
    ) -> Result<(), InputError> {
        self.drain_events()?;
        if let Some((x, y)) = at {
            self.do_move_to(x, y)?;
        }
        if pressed {
            if self.buttons.insert(button) {
                self.fake(BUTTON_PRESS_EVENT, button.x11(), 0, 0)?;
            }
        } else if self.buttons.remove(&button) {
            self.fake(BUTTON_RELEASE_EVENT, button.x11(), 0, 0)?;
        }
        self.conn.flush()?;
        Ok(())
    }

    fn move_to(&mut self, x: i32, y: i32) -> Result<(), InputError> {
        self.drain_events()?;
        self.do_move_to(x, y)?;
        self.conn.flush()?;
        Ok(())
    }

    fn move_by(&mut self, dx: i32, dy: i32) -> Result<(), InputError> {
        // Relative motion is applied by the server to the real pointer position, which is
        // already inside the screen; the server clamps at the edges.
        let dx = dx.clamp(-MAX_RELATIVE_STEP, MAX_RELATIVE_STEP) as i16;
        let dy = dy.clamp(-MAX_RELATIVE_STEP, MAX_RELATIVE_STEP) as i16;
        if dx == 0 && dy == 0 {
            return Ok(());
        }
        self.fake(MOTION_NOTIFY_EVENT, 1, dx, dy)?;
        self.conn.flush()?;
        Ok(())
    }

    fn scroll(&mut self, dx: i32, dy: i32) -> Result<(), InputError> {
        let up = take_clicks(&mut self.acc_y, dy);
        let right = take_clicks(&mut self.acc_x, dx);
        for _ in 0..up.unsigned_abs() {
            self.wheel_click(if up > 0 { 4 } else { 5 })?;
        }
        for _ in 0..right.unsigned_abs() {
            self.wheel_click(if right > 0 { 7 } else { 6 })?;
        }
        if up != 0 || right != 0 {
            self.conn.flush()?;
        }
        Ok(())
    }

    fn release_all(&mut self) -> Result<(), InputError> {
        self.acc_x = 0;
        self.acc_y = 0;
        let keys = std::mem::take(&mut self.keys);
        let buttons = std::mem::take(&mut self.buttons);
        let mut result = Ok(());
        // Keep going after an error so as much as possible is released.
        for kc in keys {
            if let Err(e) = self.fake(KEY_RELEASE_EVENT, kc, 0, 0) {
                result = Err(e);
            }
        }
        for b in buttons {
            if let Err(e) = self.fake(BUTTON_RELEASE_EVENT, b.x11(), 0, 0) {
                result = Err(e);
            }
        }
        if let Err(e) = self.conn.flush() {
            result = Err(e.into());
        }
        result
    }
}

impl Drop for X11Input {
    fn drop(&mut self) {
        let _ = self.release_all();
        // Closing right after a flush can race the server's reading of the requests: a round
        // trip makes sure the releases were executed before the connection goes away.
        let _ = self.conn.get_input_focus().map(|c| c.reply());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scroll_accumulates_whole_notches() {
        let mut acc = 0;
        assert_eq!(take_clicks(&mut acc, 60), 0);
        assert_eq!(take_clicks(&mut acc, 60), 1);
        assert_eq!(acc, 0);
        assert_eq!(take_clicks(&mut acc, 130), 1);
        assert_eq!(acc, 10);
        assert_eq!(take_clicks(&mut acc, 110), 1);
        assert_eq!(acc, 0);
        assert_eq!(take_clicks(&mut acc, -240), -2);
    }

    #[test]
    fn reversing_direction_drops_the_remainder() {
        let mut acc = 0;
        assert_eq!(take_clicks(&mut acc, 100), 0);
        // 100 up then 100 down must not cancel into a stray click either way.
        assert_eq!(take_clicks(&mut acc, -100), 0);
        assert_eq!(acc, -100);
        assert_eq!(take_clicks(&mut acc, -20), -1);
    }

    #[test]
    fn hostile_scroll_is_bounded() {
        let mut acc = 0;
        assert_eq!(take_clicks(&mut acc, i32::MAX), MAX_SCROLL_CLICKS);
        assert_eq!(take_clicks(&mut acc, i32::MAX), MAX_SCROLL_CLICKS);
        let mut acc = 0;
        assert_eq!(take_clicks(&mut acc, i32::MIN), -MAX_SCROLL_CLICKS);
    }
}
