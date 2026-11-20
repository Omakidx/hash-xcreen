//! Screen capture backends. One [`Capture`] implementation per display stack; X11 first.
//!
//! The model is change-driven: a backend reports damage, the caller decides when to take
//! a frame (pacing is the caller's business), and no damage means no capture. Cursor shape
//! and position travel on their own event stream, never inside the video frames.
//!
//! ```no_run
//! use hx_capture::{Capture, X11Capture, X11Config};
//! use std::time::Duration;
//!
//! # fn main() -> Result<(), hx_capture::CaptureError> {
//! let mut cap = X11Capture::connect(&X11Config::default())?;
//! loop {
//!     cap.wait(Some(Duration::from_millis(50)))?;
//!     if cap.damage_pending() {
//!         if let Some(frame) = cap.grab(Duration::from_millis(5))? {
//!             println!("{}x{} frame, {} damaged rects", frame.size().width, frame.size().height, frame.damage().len());
//!         }
//!     }
//! }
//! # }
//! ```
//!
//! Input injection (XTest) lives in [`input`]: physical-scancode keyboard, clamped pointer,
//! accumulated scrolling, and release-on-disconnect, behind the [`InputInjector`] trait.

#![deny(unsafe_code)]

pub mod clipboard;
mod clock;
mod cursor;
mod error;
mod frame;
mod geometry;
mod hid;
pub mod input;
mod shm;
mod x11;

pub use clock::mono_ns;
pub use cursor::{CursorEvent, CursorPosition, CursorShape};
pub use error::CaptureError;
pub use frame::{Frame, PixelFormat};
pub use geometry::{Rect, Size};
pub use input::{Button, InputError, InputInjector, X11Input};
pub use x11::{X11Capture, X11Config};

use std::time::Duration;

/// What [`Capture::wait`] observed since the previous call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wake {
    /// New screen damage arrived.
    pub damage: bool,
    /// Cursor events are queued for [`Capture::drain_cursor`].
    pub cursor: bool,
    /// The screen size changed; the next frame has this size.
    pub resized: Option<Size>,
}

/// A source of screen frames and cursor events.
///
/// Implementations are single-consumer: one thread calls these methods. Frames are `Send`
/// and return their buffer to the backend's pool when dropped, so a slow consumer applies
/// backpressure (no free buffer) instead of growing memory.
pub trait Capture: Send {
    /// Current screen size in pixels.
    fn size(&self) -> Size;

    /// Block until something new happens (damage, cursor, resize) or `timeout` elapses
    /// (`None` waits indefinitely). Returns immediately if something new was already seen.
    /// Does not consume damage; see [`Capture::damage_pending`] and [`Capture::grab`].
    fn wait(&mut self, timeout: Option<Duration>) -> Result<Wake, CaptureError>;

    /// True while damage is accumulated and not yet captured (or a capture was forced).
    fn damage_pending(&self) -> bool;

    /// Time (see [`mono_ns`]) the oldest uncaptured damage arrived, if any.
    fn damage_since_ns(&self) -> Option<u64>;

    /// Make the next [`Capture::grab`] produce a full-screen frame even without damage
    /// (a new client connected, or a resync was requested).
    fn force_full_frame(&mut self);

    /// Capture the screen if damage is pending. Returns `Ok(None)` when there is nothing to
    /// capture, or when no free buffer became available within `buffer_wait` (the damage stays
    /// pending in that case).
    fn grab(&mut self, buffer_wait: Duration) -> Result<Option<Frame>, CaptureError>;

    /// Ask the display to change to `size` (matching the client window). The change is
    /// visible through [`Wake::resized`] and the size of later frames.
    fn request_resize(&mut self, size: Size) -> Result<(), CaptureError>;

    /// Hand queued cursor events to `sink`, oldest first. Position events are coalesced.
    fn drain_cursor(&mut self, sink: &mut dyn FnMut(CursorEvent));

    /// Queue the current cursor shape again (a new client needs it).
    fn refresh_cursor(&mut self) -> Result<(), CaptureError>;
}
