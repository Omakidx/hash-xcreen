//! USB HID keyboard usages (page 0x07) to Linux evdev key codes.
//!
//! The table follows the Linux HID driver's usage map. X servers using the evdev keycode set
//! (Xorg, Xvfb, XWayland) number their keycodes `evdev + 8`, so a physical key sent by the
//! client lands on the same physical key whatever layout either side uses.

/// Highest usage on the Keyboard/Keypad page the protocol accepts (right GUI).
pub const MAX_USAGE: u8 = 0xE7;

#[rustfmt::skip]
static HID_TO_EVDEV: [u16; 0xE8] = [
    0, 0, 0, 0, 30, 48, 46, 32, 18, 33, 34, 35,
    23, 36, 37, 38, 50, 49, 24, 25, 16, 19, 31, 20,
    22, 47, 17, 45, 21, 44, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 28, 1, 14, 15, 57, 12, 13, 26,
    27, 43, 43, 39, 40, 41, 51, 52, 53, 58, 59, 60,
    61, 62, 63, 64, 65, 66, 67, 68, 87, 88, 99, 70,
    119, 110, 102, 104, 111, 107, 109, 106, 105, 108, 103, 69,
    98, 55, 74, 78, 96, 79, 80, 81, 75, 76, 77, 71,
    72, 73, 82, 83, 86, 127, 116, 117, 183, 184, 185, 186,
    187, 188, 189, 190, 191, 192, 193, 194, 134, 138, 130, 132,
    128, 129, 131, 137, 133, 135, 136, 113, 115, 114, 0, 0,
    0, 121, 0, 89, 93, 124, 92, 94, 95, 0, 0, 0,
    122, 123, 90, 91, 85, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 29, 42, 56, 125,
    97, 54, 100, 126,
];

/// Evdev code for a HID keyboard usage, or `None` for usages with no key (reserved, error
/// roll-over, locking keys, unassigned).
pub fn hid_to_evdev(usage: u8) -> Option<u16> {
    HID_TO_EVDEV
        .get(usize::from(usage))
        .copied()
        .filter(|c| *c != 0)
}

/// The X keycode for an evdev code (evdev keycode set: code plus 8).
pub fn evdev_to_x11(code: u16) -> u8 {
    (code + 8).min(255) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_digits_and_modifiers() {
        assert_eq!(hid_to_evdev(0x04), Some(30)); // A
        assert_eq!(hid_to_evdev(0x1D), Some(44)); // Z
        assert_eq!(hid_to_evdev(0x1E), Some(2)); // 1
        assert_eq!(hid_to_evdev(0x27), Some(11)); // 0
        assert_eq!(hid_to_evdev(0x28), Some(28)); // Enter
        assert_eq!(hid_to_evdev(0x2C), Some(57)); // Space
        assert_eq!(hid_to_evdev(0xE0), Some(29)); // left Ctrl
        assert_eq!(hid_to_evdev(0xE1), Some(42)); // left Shift
        assert_eq!(hid_to_evdev(0xE7), Some(126)); // right GUI
        assert_eq!(evdev_to_x11(30), 38); // the keycode xev shows for A
    }

    #[test]
    fn gaps_are_unmapped() {
        for u in [0x00, 0x01, 0x02, 0x03, 0x82, 0xA5, 0xDF] {
            assert_eq!(hid_to_evdev(u), None, "{u:#x}");
        }
    }

    #[test]
    fn mapped_codes_are_unique_and_fit_an_x_keycode() {
        let mut seen = std::collections::HashSet::new();
        for u in 0..=MAX_USAGE {
            if let Some(c) = hid_to_evdev(u) {
                assert!(c < 248, "usage {u:#x} -> {c}");
                // 0x32 (non-US #) shares KEY_BACKSLASH with 0x31, as in the Linux driver.
                if u != 0x32 {
                    assert!(seen.insert(c), "duplicate evdev code {c} at usage {u:#x}");
                }
            }
        }
    }
}
