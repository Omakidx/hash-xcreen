//! The "terminal" of the end-to-end run: a small X client that reacts to the input the session
//! injects and paints a mark the client can read back out of the decoded video. It stands in for
//! xterm (not available on CI runners) and makes latency measurable without reading text:
//!
//! * **Typing.** Each key press paints a glyph at the cursor cell and moves a solid black
//!   cursor block to the next cell. Event `i` is *seen* when cell `i + 1` of the typing line is
//!   black in a decoded picture.
//! * **Scrolling.** The first wheel event clears the window; each wheel event then scrolls the
//!   window up one row and paints a new, text-dense bottom row that starts with a 13 cell bar
//!   code: a black start cell and the 12 bits of the event counter. Event `j` is *seen* when the
//!   bottom row's code reads at least `j`.
//! * **F12** dumps the window as one byte per pixel (255 white, 0 black) to a file, so the
//!   client can compare what it decoded with what the server drew.
//!
//! Marks are pure black on pure white, so detection survives H.264 at any sensible rate; the
//! geometry is shared with the reader ([`Geometry`]).
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};

use x11rb::COPY_FROM_PARENT;
use x11rb::connection::Connection;
use x11rb::protocol::Event;
use x11rb::protocol::xproto::{
    ConnectionExt as _, CreateGCAux, CreateWindowAux, EventMask, ImageFormat, Rectangle,
    WindowClass,
};
use x11rb::rust_connection::RustConnection;

pub const CELL_W: u32 = 12;
pub const CELL_H: u32 = 24;
/// The X keycode F12 arrives as (evdev 88 + 8).
pub const F12_KEYCODE: u8 = 96;
/// Row of the typing line (two blank rows above it).
pub const TYPING_ROW: u32 = 2;
/// Bits in the scroll counter.
pub const CODE_BITS: u32 = 12;

#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    pub width: u32,
    pub height: u32,
}

impl Geometry {
    pub fn cols(&self) -> u32 {
        self.width / CELL_W
    }
    pub fn rows(&self) -> u32 {
        self.height / CELL_H
    }
    /// (row, col) of the cursor after the `i`-th typed key (0-based).
    pub fn typing_cell(&self, i: u32) -> (u32, u32) {
        let p = TYPING_ROW * self.cols() + i + 1;
        (p / self.cols(), p % self.cols())
    }
    /// How many keys fit before the line would wrap (the test types well below it).
    pub fn typing_capacity(&self) -> u32 {
        self.cols() - 2
    }
}

/// Mean luma of the bottom six rows of a cell: a solid cursor block reads near 0, a glyph (which
/// keeps clear of those rows) or a blank cell near 255.
pub fn cell_is_cursor(luma: &[u8], width: u32, row: u32, col: u32) -> bool {
    let (x0, y0) = (col * CELL_W, row * CELL_H + CELL_H - 6);
    let mut sum = 0u32;
    for y in y0..y0 + 6 {
        let r = (y * width + x0) as usize;
        sum += luma[r..r + CELL_W as usize]
            .iter()
            .map(|&v| u32::from(v))
            .sum::<u32>();
    }
    sum / (6 * CELL_W) < 100
}

/// The highest typing cell in `from..=to` (event indices) that shows the cursor, if any. A
/// decoded picture can skip cursor positions when frames coalesce, so the newest one seen
/// answers for every earlier event.
pub fn newest_cursor(luma: &[u8], g: Geometry, from: u32, to: u32) -> Option<u32> {
    (from..=to).rev().find(|&j| {
        let (r, c) = g.typing_cell(j);
        cell_is_cursor(luma, g.width, r, c)
    })
}

/// The counter painted into the bottom row; `None` when the start cell is not black (the screen
/// is not in scroll mode yet).
pub fn read_scroll_code(luma: &[u8], g: Geometry) -> Option<u32> {
    let y = (g.rows() - 1) * CELL_H + CELL_H / 2;
    let cell = |k: u32| -> u32 {
        let x = k * CELL_W + CELL_W / 2;
        let mut sum = 0u32;
        for dy in 0..3 {
            for dx in 0..4 {
                sum += u32::from(luma[((y - 1 + dy) * g.width + x - 2 + dx) as usize]);
            }
        }
        sum / 12
    };
    if cell(0) >= 128 {
        return None;
    }
    let mut v = 0u32;
    for b in 0..CODE_BITS {
        v = (v << 1) | u32::from(cell(1 + b) < 128);
    }
    Some(v)
}

fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

pub struct Desk {
    pub dump: PathBuf,
    /// Key presses, wheel events and dumps handled.
    pub handled: Arc<AtomicU64>,
    _thread: std::thread::JoinHandle<()>,
}

impl Desk {
    /// Opens the window on `display` and starts reacting to input. The thread ends when the X
    /// connection does (Xvfb is killed).
    pub fn start(display: &str, g: Geometry, dump: PathBuf) -> Desk {
        let display = display.to_owned();
        let handled = Arc::new(AtomicU64::new(0));
        let (h2, d2) = (handled.clone(), dump.clone());
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            if let Err(e) = run(&display, g, &d2, &h2, &ready_tx) {
                eprintln!("desk: {e}");
            }
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("the desk window did not open");
        Desk {
            dump,
            handled,
            _thread: thread,
        }
    }
}

struct Painter<'a> {
    conn: &'a RustConnection,
    win: u32,
    black: u32,
    white: u32,
    g: Geometry,
}

impl Painter<'_> {
    fn rect(&self, gc: u32, x: u32, y: u32, w: u32, h: u32) {
        let _ = self.conn.poly_fill_rectangle(
            self.win,
            gc,
            &[Rectangle {
                x: x as i16,
                y: y as i16,
                width: w as u16,
                height: h as u16,
            }],
        );
    }

    fn clear(&self) {
        self.rect(self.white, 0, 0, self.g.width, self.g.height);
    }

    fn cell(&self, row: u32, col: u32, gc: u32) {
        self.rect(gc, col * CELL_W, row * CELL_H, CELL_W, CELL_H);
    }

    /// A letter-like glyph: three to five 2 px strokes (bars and stems) picked from `seed`, kept
    /// to the cell's upper 18 rows. Structured like text, not like noise, so the codec treats it
    /// the way it treats a terminal.
    fn glyph(&self, x: u32, y: u32, seed: u64) {
        let mut bits = mix(seed);
        let mut rects = Vec::new();
        let (w, h) = (10u32, 14u32);
        for _ in 0..3 + (bits & 1) as u32 + ((bits >> 1) & 1) as u32 {
            bits = mix(bits);
            let (kind, pos) = (bits & 3, (bits >> 2) % 3);
            let (rx, ry, rw, rh) = match kind {
                0 => (0, pos as u32 * 6, w, 2),                 // a horizontal bar
                1 => (pos as u32 * 4, 0, 2, h),                 // a full-height stem
                2 => (pos as u32 * 4, 0, 2, h / 2 + 2),         // an upper stem
                _ => (pos as u32 * 4, h / 2 - 1, 2, h / 2 + 1), // a lower stem
            };
            rects.push(Rectangle {
                x: (x + rx) as i16,
                y: (y + 2 + ry) as i16,
                width: rw as u16,
                height: rh as u16,
            });
        }
        let _ = self.conn.poly_fill_rectangle(self.win, self.black, &rects);
    }

    fn type_key(&self, keycode: u8, i: u64) {
        let (row, col) = self.cursor(i);
        self.cell(row, col, self.white);
        self.glyph(col * CELL_W, row * CELL_H, u64::from(keycode) * 977 + i);
        let (nr, nc) = self.cursor(i + 1);
        self.cell(nr, nc, self.black);
    }

    fn cursor(&self, i: u64) -> (u32, u32) {
        let p = u64::from(TYPING_ROW * self.g.cols()) + i;
        (
            (p / u64::from(self.g.cols())) as u32,
            (p % u64::from(self.g.cols())) as u32,
        )
    }

    /// Scrolls up one row and paints line `n` at the bottom.
    fn scroll_line(&self, n: u32) {
        let (w, h) = (self.g.width, self.g.height);
        let rows = self.g.rows();
        let keep = (rows - 1) * CELL_H;
        let _ = self.conn.copy_area(
            self.win,
            self.win,
            self.white,
            0,
            CELL_H as i16,
            0,
            0,
            w as u16,
            keep as u16,
        );
        let y = (rows - 1) * CELL_H;
        // Everything under the last row as well (the display may not be a whole number of rows).
        self.rect(self.white, 0, y, w, h - y);
        // The code: a black start cell, then the bits, most significant first.
        self.cell(rows - 1, 0, self.black);
        for b in 0..CODE_BITS {
            if n >> (CODE_BITS - 1 - b) & 1 == 1 {
                self.cell(rows - 1, 1 + b, self.black);
            }
        }
        // Dense text after it.
        let start = CODE_BITS + 2;
        for c in start..self.g.cols().saturating_sub(1) {
            self.glyph(c * CELL_W, y, u64::from(n) * 131 + u64::from(c));
        }
    }
}

fn run(
    display: &str,
    g: Geometry,
    dump: &std::path::Path,
    handled: &AtomicU64,
    ready: &std::sync::mpsc::Sender<()>,
) -> Result<(), String> {
    let (conn, n) = RustConnection::connect(Some(display)).map_err(|e| e.to_string())?;
    let root = conn.setup().roots[n].root;
    let white_px = conn.setup().roots[n].white_pixel;
    let black_px = conn.setup().roots[n].black_pixel;
    let win = conn.generate_id().map_err(|e| e.to_string())?;
    conn.create_window(
        COPY_FROM_PARENT as u8,
        win,
        root,
        0,
        0,
        g.width as u16,
        g.height as u16,
        0,
        WindowClass::INPUT_OUTPUT,
        0,
        &CreateWindowAux::new()
            .background_pixel(white_px)
            .event_mask(EventMask::KEY_PRESS | EventMask::BUTTON_PRESS),
    )
    .map_err(|e| e.to_string())?;
    let mut gcs = [0u32; 2];
    for (gc, px) in gcs.iter_mut().zip([black_px, white_px]) {
        *gc = conn.generate_id().map_err(|e| e.to_string())?;
        conn.create_gc(
            *gc,
            win,
            &CreateGCAux::new().foreground(px).graphics_exposures(0),
        )
        .map_err(|e| e.to_string())?;
    }
    conn.map_window(win).map_err(|e| e.to_string())?;
    let p = Painter {
        conn: &conn,
        win,
        black: gcs[0],
        white: gcs[1],
        g,
    };
    p.clear();
    // The initial cursor, where the first key lands.
    let (r, c) = p.cursor(0);
    p.cell(r, c, p.black);
    conn.flush().map_err(|e| e.to_string())?;
    conn.get_input_focus()
        .map_err(|e| e.to_string())?
        .reply()
        .map_err(|e| e.to_string())?;
    let _ = ready.send(());

    let (mut typed, mut lines) = (0u64, 0u32);
    let mut scroll_mode = false;
    loop {
        let ev = conn.wait_for_event().map_err(|e| e.to_string())?;
        match ev {
            Event::KeyPress(k) if k.detail == F12_KEYCODE => {
                dump_window(&conn, win, g, dump);
                handled.fetch_add(1, SeqCst);
            }
            Event::KeyPress(k) => {
                if !scroll_mode && typed < u64::from(g.typing_capacity()) {
                    p.type_key(k.detail, typed);
                    typed += 1;
                    let _ = conn.flush();
                }
                handled.fetch_add(1, SeqCst);
            }
            Event::ButtonPress(b) if b.detail == 4 || b.detail == 5 => {
                if !scroll_mode {
                    scroll_mode = true;
                    p.clear();
                }
                lines += 1;
                p.scroll_line(lines);
                let _ = conn.flush();
                handled.fetch_add(1, SeqCst);
            }
            _ => {}
        }
    }
}

fn dump_window(conn: &RustConnection, win: u32, g: Geometry, path: &std::path::Path) {
    let Ok(cookie) = conn.get_image(
        ImageFormat::Z_PIXMAP,
        win,
        0,
        0,
        g.width as u16,
        g.height as u16,
        u32::MAX,
    ) else {
        return;
    };
    let Ok(img) = cookie.reply() else { return };
    // 32 bits per pixel, B G R X: a pixel is white when its red byte is high.
    let bpp = img.data.len() / (g.width * g.height) as usize;
    let mask: Vec<u8> = img
        .data
        .chunks(bpp.max(1))
        .map(|px| {
            if px.get(2).copied().unwrap_or(0) > 127 {
                255
            } else {
                0
            }
        })
        .collect();
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, &mask).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank(g: Geometry) -> Vec<u8> {
        vec![255u8; (g.width * g.height) as usize]
    }

    fn black_cell(luma: &mut [u8], g: Geometry, row: u32, col: u32) {
        for y in row * CELL_H..(row + 1) * CELL_H {
            for x in col * CELL_W..(col + 1) * CELL_W {
                luma[(y * g.width + x) as usize] = 0;
            }
        }
    }

    #[test]
    fn the_cursor_cell_is_found_and_a_blank_one_is_not() {
        let g = Geometry {
            width: 1280,
            height: 720,
        };
        let mut l = blank(g);
        let (r, c) = g.typing_cell(4);
        assert!(!cell_is_cursor(&l, g.width, r, c));
        black_cell(&mut l, g, r, c);
        assert!(cell_is_cursor(&l, g.width, r, c));
        assert!(!cell_is_cursor(&l, g.width, r, c + 1));
    }

    #[test]
    fn the_newest_cursor_answers_for_skipped_positions() {
        let g = Geometry {
            width: 1280,
            height: 720,
        };
        let mut l = blank(g);
        let (r, c) = g.typing_cell(7);
        black_cell(&mut l, g, r, c);
        assert_eq!(newest_cursor(&l, g, 3, 9), Some(7));
        assert_eq!(newest_cursor(&l, g, 8, 9), None);
        assert_eq!(newest_cursor(&l, g, 0, 7), Some(7));
    }

    #[test]
    fn the_scroll_code_round_trips_and_needs_its_start_cell() {
        let g = Geometry {
            width: 1280,
            height: 720,
        };
        let mut l = blank(g);
        assert_eq!(read_scroll_code(&l, g), None);
        let n = 0b1010_0110_0101u32;
        black_cell(&mut l, g, g.rows() - 1, 0);
        for b in 0..CODE_BITS {
            if n >> (CODE_BITS - 1 - b) & 1 == 1 {
                black_cell(&mut l, g, g.rows() - 1, 1 + b);
            }
        }
        assert_eq!(read_scroll_code(&l, g), Some(n));
    }

    #[test]
    fn typing_cells_advance_along_the_line_and_wrap() {
        let g = Geometry {
            width: 1280,
            height: 720,
        };
        assert_eq!(g.typing_cell(0), (TYPING_ROW, 1));
        assert_eq!(g.typing_cell(g.cols() - 1), (TYPING_ROW + 1, 0));
    }
}
