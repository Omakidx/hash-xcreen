//! Input: physical keys as USB HID usages (layout independent, protocol 5.3), the pointer
//! mapped between the view and the remote screen, scroll units, and the one shortcut the app
//! keeps for itself (the toolbar chord).

use hx_proto::pb::MouseButton;
use slint::winit_030::winit::keyboard::KeyCode;

/// The USB HID usage (page 0x07) of a physical key, or `None` for keys with no usage.
pub fn hid_usage(k: KeyCode) -> Option<u32> {
    use KeyCode::*;
    Some(match k {
        KeyA => 0x04, KeyB => 0x05, KeyC => 0x06, KeyD => 0x07, KeyE => 0x08, KeyF => 0x09,
        KeyG => 0x0A, KeyH => 0x0B, KeyI => 0x0C, KeyJ => 0x0D, KeyK => 0x0E, KeyL => 0x0F,
        KeyM => 0x10, KeyN => 0x11, KeyO => 0x12, KeyP => 0x13, KeyQ => 0x14, KeyR => 0x15,
        KeyS => 0x16, KeyT => 0x17, KeyU => 0x18, KeyV => 0x19, KeyW => 0x1A, KeyX => 0x1B,
        KeyY => 0x1C, KeyZ => 0x1D,
        Digit1 => 0x1E, Digit2 => 0x1F, Digit3 => 0x20, Digit4 => 0x21, Digit5 => 0x22,
        Digit6 => 0x23, Digit7 => 0x24, Digit8 => 0x25, Digit9 => 0x26, Digit0 => 0x27,
        Enter => 0x28, Escape => 0x29, Backspace => 0x2A, Tab => 0x2B, Space => 0x2C,
        Minus => 0x2D, Equal => 0x2E, BracketLeft => 0x2F, BracketRight => 0x30,
        Backslash => 0x31, Semicolon => 0x33, Quote => 0x34, Backquote => 0x35,
        Comma => 0x36, Period => 0x37, Slash => 0x38, CapsLock => 0x39,
        F1 => 0x3A, F2 => 0x3B, F3 => 0x3C, F4 => 0x3D, F5 => 0x3E, F6 => 0x3F,
        F7 => 0x40, F8 => 0x41, F9 => 0x42, F10 => 0x43, F11 => 0x44, F12 => 0x45,
        PrintScreen => 0x46, ScrollLock => 0x47, Pause => 0x48, Insert => 0x49,
        Home => 0x4A, PageUp => 0x4B, Delete => 0x4C, End => 0x4D, PageDown => 0x4E,
        ArrowRight => 0x4F, ArrowLeft => 0x50, ArrowDown => 0x51, ArrowUp => 0x52,
        NumLock => 0x53, NumpadDivide => 0x54, NumpadMultiply => 0x55, NumpadSubtract => 0x56,
        NumpadAdd => 0x57, NumpadEnter => 0x58,
        Numpad1 => 0x59, Numpad2 => 0x5A, Numpad3 => 0x5B, Numpad4 => 0x5C, Numpad5 => 0x5D,
        Numpad6 => 0x5E, Numpad7 => 0x5F, Numpad8 => 0x60, Numpad9 => 0x61, Numpad0 => 0x62,
        NumpadDecimal => 0x63, IntlBackslash => 0x64, ContextMenu => 0x65,
        F13 => 0x68, F14 => 0x69, F15 => 0x6A, F16 => 0x6B, F17 => 0x6C, F18 => 0x6D,
        F19 => 0x6E, F20 => 0x6F, F21 => 0x70, F22 => 0x71, F23 => 0x72, F24 => 0x73,
        ControlLeft => 0xE0, ShiftLeft => 0xE1, AltLeft => 0xE2, SuperLeft => 0xE3,
        ControlRight => 0xE4, ShiftRight => 0xE5, AltRight => 0xE6, SuperRight => 0xE7,
        _ => return None,
    })
}

/// A key combination of the Keys menu: usages pressed in order, released in reverse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Combo {
    /// Ctrl+Alt+Del.
    CtrlAltDel,
    /// Alt+Tab.
    AltTab,
    /// Alt+F4.
    AltF4,
    /// The Super (Windows) key.
    Super,
}

impl Combo {
    /// The usages, in press order.
    pub fn usages(self) -> &'static [u32] {
        match self {
            Self::CtrlAltDel => &[0xE0, 0xE2, 0x4C],
            Self::AltTab => &[0xE2, 0x2B],
            Self::AltF4 => &[0xE2, 0x3D],
            Self::Super => &[0xE3],
        }
    }

    /// Press events then release events (key, pressed).
    pub fn events(self) -> Vec<(u32, bool)> {
        let u = self.usages();
        u.iter()
            .map(|k| (*k, true))
            .chain(u.iter().rev().map(|k| (*k, false)))
            .collect()
    }
}

/// How the remote picture is laid out in the view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fit {
    /// Scaled to fit, keeping the aspect ratio.
    Fit,
    /// 1:1, centred.
    Actual,
    /// The remote screen is resized to the window (1:1, no letterbox).
    Resize,
}

/// Maps between view coordinates (logical pixels of the picture area) and remote pixels.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ViewTransform {
    /// Remote size in pixels.
    pub remote: (u32, u32),
    /// View size in logical pixels.
    pub view: (f32, f32),
    /// Layout.
    pub fit: Fit,
}

impl ViewTransform {
    /// The rectangle (x, y, w, h) the picture occupies in the view.
    pub fn rect(&self) -> (f32, f32, f32, f32) {
        let (rw, rh) = (self.remote.0 as f32, self.remote.1 as f32);
        let (vw, vh) = self.view;
        if rw <= 0.0 || rh <= 0.0 {
            return (0.0, 0.0, vw, vh);
        }
        let (w, h) = match self.fit {
            Fit::Fit => {
                let s = (vw / rw).min(vh / rh);
                (rw * s, rh * s)
            }
            Fit::Actual | Fit::Resize => (rw, rh),
        };
        ((vw - w) / 2.0, (vh - h) / 2.0, w, h)
    }

    /// A view point to a remote pixel, clamped into the picture. `None` outside it.
    pub fn to_remote(&self, x: f32, y: f32) -> Option<(i32, i32)> {
        let (ox, oy, w, h) = self.rect();
        if w <= 0.0 || h <= 0.0 || x < ox || y < oy || x >= ox + w || y >= oy + h {
            return None;
        }
        let rx = ((x - ox) / w * self.remote.0 as f32) as i32;
        let ry = ((y - oy) / h * self.remote.1 as f32) as i32;
        Some((rx.clamp(0, self.remote.0 as i32 - 1), ry.clamp(0, self.remote.1 as i32 - 1)))
    }

    /// A remote pixel to a view point.
    pub fn to_view(&self, rx: i32, ry: i32) -> (f32, f32) {
        let (ox, oy, w, h) = self.rect();
        (
            ox + rx as f32 / self.remote.0.max(1) as f32 * w,
            oy + ry as f32 / self.remote.1.max(1) as f32 * h,
        )
    }
}

/// Slint pointer button to the protocol's.
pub fn mouse_button(b: slint::platform::PointerEventButton) -> Option<MouseButton> {
    use slint::platform::PointerEventButton as P;
    Some(match b {
        P::Left => MouseButton::Left,
        P::Right => MouseButton::Right,
        P::Middle => MouseButton::Middle,
        P::Back => MouseButton::Back,
        P::Forward => MouseButton::Forward,
        _ => return None,
    })
}

/// Scroll in logical pixels to 1/120 of a wheel notch (protocol 5.3: positive dy scrolls up).
/// One notch is 60 logical pixels in Slint, so the factor is 2; the result is clamped to a
/// reasonable burst.
pub fn scroll_units(delta: f32) -> i32 {
    (delta * 2.0).round().clamp(-2400.0, 2400.0) as i32
}

/// Detects the toolbar chord: Ctrl, Alt and Shift all down. Returns true once per press of
/// the chord (when the last of the three goes down).
#[derive(Debug, Default)]
pub struct ChordDetector {
    ctrl: bool,
    alt: bool,
    shift: bool,
    fired: bool,
}

impl ChordDetector {
    /// Feeds the current modifier state. True exactly when the chord became complete.
    pub fn update(&mut self, ctrl: bool, alt: bool, shift: bool) -> bool {
        self.ctrl = ctrl;
        self.alt = alt;
        self.shift = shift;
        let all = ctrl && alt && shift;
        if all && !self.fired {
            self.fired = true;
            return true;
        }
        if !all {
            self.fired = false;
        }
        false
    }
}

/// Keys currently held, so a lost focus or a dropped connection can release them.
#[derive(Debug, Default)]
pub struct Held {
    keys: std::collections::BTreeSet<u32>,
}

impl Held {
    /// Records a press or release. Returns false for a repeat press of a held key (auto-repeat
    /// is the remote's job, not ours).
    pub fn key(&mut self, usage: u32, pressed: bool) -> bool {
        if pressed {
            self.keys.insert(usage)
        } else {
            self.keys.remove(&usage)
        }
    }
    /// True if anything is held.
    pub fn any(&self) -> bool {
        !self.keys.is_empty()
    }
    /// Forgets everything (after `ReleaseAll`).
    pub fn clear(&mut self) {
        self.keys.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usages_are_valid_protocol_values_and_unique() {
        use KeyCode::*;
        let all = [
            KeyA, KeyZ, Digit1, Digit0, Enter, Escape, Backspace, Tab, Space, F1, F12, ArrowUp,
            ArrowLeft, Numpad0, NumpadEnter, ControlLeft, SuperRight, Delete, IntlBackslash,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for k in all {
            let u = hid_usage(k).expect("mapped");
            assert!(u <= 0xE7, "{k:?} {u:#x}");
            assert!(seen.insert(u), "{k:?} duplicates {u:#x}");
        }
        assert_eq!(hid_usage(KeyA), Some(0x04));
        assert_eq!(hid_usage(Digit0), Some(0x27));
        assert_eq!(hid_usage(Enter), Some(0x28));
        assert_eq!(hid_usage(Escape), Some(0x29));
        assert_eq!(hid_usage(AudioVolumeUp), None);
    }

    #[test]
    fn combos_press_in_order_and_release_in_reverse() {
        let e = Combo::CtrlAltDel.events();
        assert_eq!(e.first(), Some(&(0xE0, true)));
        assert_eq!(e[2], (0x4C, true));
        assert_eq!(e[3], (0x4C, false));
        assert_eq!(e.last(), Some(&(0xE0, false)));
        assert_eq!(e.len(), 6);
    }

    #[test]
    fn fit_maps_pointer_and_letterboxes() {
        let t = ViewTransform { remote: (1920, 1080), view: (960.0, 700.0), fit: Fit::Fit };
        let (ox, oy, w, h) = t.rect();
        assert_eq!(w, 960.0);
        assert_eq!(h, 540.0);
        assert_eq!((ox, oy), (0.0, 80.0));
        assert_eq!(t.to_remote(480.0, 350.0), Some((960, 540)));
        assert_eq!(t.to_remote(10.0, 10.0), None, "letterbox");
        assert_eq!(t.to_remote(959.9, 619.9).map(|p| p.0), Some(1919));
        let (vx, vy) = t.to_view(960, 540);
        assert!((vx - 480.0).abs() < 0.5 && (vy - 350.0).abs() < 0.5);
    }

    #[test]
    fn actual_size_is_one_to_one_and_centred() {
        let t = ViewTransform { remote: (800, 600), view: (1000.0, 700.0), fit: Fit::Actual };
        assert_eq!(t.rect(), (100.0, 50.0, 800.0, 600.0));
        assert_eq!(t.to_remote(100.0, 50.0), Some((0, 0)));
        assert_eq!(t.to_remote(99.0, 50.0), None);
    }

    #[test]
    fn scroll_is_clamped_and_signed() {
        assert_eq!(scroll_units(60.0), 120);
        assert_eq!(scroll_units(-60.0), -120);
        assert_eq!(scroll_units(1.0e9), 2400);
    }

    #[test]
    fn chord_fires_once_per_press() {
        let mut c = ChordDetector::default();
        assert!(!c.update(true, false, false));
        assert!(!c.update(true, true, false));
        assert!(c.update(true, true, true));
        assert!(!c.update(true, true, true));
        assert!(!c.update(false, true, true));
        assert!(c.update(true, true, true));
    }

    #[test]
    fn held_keys_ignore_repeats() {
        let mut h = Held::default();
        assert!(h.key(4, true));
        assert!(!h.key(4, true));
        assert!(h.any());
        assert!(h.key(4, false));
        assert!(!h.any());
    }

    #[test]
    fn buttons_map() {
        use slint::platform::PointerEventButton as P;
        assert_eq!(mouse_button(P::Left), Some(MouseButton::Left));
        assert_eq!(mouse_button(P::Other), None);
    }
}
