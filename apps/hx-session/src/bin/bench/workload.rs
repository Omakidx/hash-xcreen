//! Synthetic screen workloads for the bench, drawn straight onto the root window.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt as _, CreateGCAux, ImageFormat, Rectangle};
use x11rb::rust_connection::RustConnection;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Draw nothing: the pipeline should do no work after the first frame.
    Idle,
    /// A small glyph-sized rectangle every 66 ms (about 15 keystrokes a second).
    Typing,
    /// A text-like 1280x720 area scrolled 6 px per frame at 60 Hz.
    Scroll,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "idle" => Some(Kind::Idle),
            "typing" => Some(Kind::Typing),
            "scroll" => Some(Kind::Scroll),
            _ => None,
        }
    }
}

/// A running workload thread.
pub struct Workload {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Duration>>,
}

impl Workload {
    pub fn start(display: Option<String>, kind: Kind) -> Result<Workload, String> {
        let stop = Arc::new(AtomicBool::new(false));
        let (conn, n) = RustConnection::connect(display.as_deref()).map_err(|e| e.to_string())?;
        let flag = stop.clone();
        let handle = std::thread::Builder::new()
            .name("hx-workload".into())
            .spawn(move || {
                let _ = draw(&conn, n, kind, &flag);
                thread_cpu()
            })
            .map_err(|e| e.to_string())?;
        Ok(Workload {
            stop,
            handle: Some(handle),
        })
    }

    /// Stop drawing; returns the CPU time the workload thread itself used.
    pub fn stop(mut self) -> Duration {
        self.stop.store(true, Relaxed);
        self.handle
            .take()
            .and_then(|h| h.join().ok())
            .unwrap_or_default()
    }
}

fn thread_cpu() -> Duration {
    let ts = rustix::time::clock_gettime(rustix::time::ClockId::ThreadCPUTime);
    Duration::new(ts.tv_sec.max(0) as u64, ts.tv_nsec.max(0) as u32)
}

fn draw(
    conn: &RustConnection,
    screen: usize,
    kind: Kind,
    stop: &AtomicBool,
) -> Result<(), Box<dyn std::error::Error>> {
    let s = &conn.setup().roots[screen];
    let (root, depth) = (s.root, s.root_depth);
    let (sw, sh) = (
        usize::from(s.width_in_pixels),
        usize::from(s.height_in_pixels),
    );
    let gc = conn.generate_id()?;
    conn.create_gc(gc, root, &CreateGCAux::new().foreground(s.white_pixel))?;
    let mut sleep_until = Instant::now();
    let mut tick = 0u64;
    match kind {
        Kind::Idle => {
            while !stop.load(Relaxed) {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        Kind::Typing => {
            let (mut x, mut y) = (40i16, 40i16);
            while !stop.load(Relaxed) {
                // Alternate white and dark so every cell really changes.
                let colour = if tick.is_multiple_of(2) {
                    s.black_pixel
                } else {
                    s.white_pixel
                };
                conn.change_gc(
                    gc,
                    &x11rb::protocol::xproto::ChangeGCAux::new().foreground(colour),
                )?;
                conn.poly_fill_rectangle(
                    root,
                    gc,
                    &[Rectangle {
                        x,
                        y,
                        width: 10,
                        height: 18,
                    }],
                )?;
                conn.flush()?;
                conn.get_input_focus()?.reply()?;
                x += 12;
                if usize::try_from(x).unwrap_or(0) + 24 > sw {
                    x = 40;
                    y += 22;
                    if usize::try_from(y).unwrap_or(0) + 40 > sh {
                        y = 40;
                    }
                }
                tick += 1;
                sleep_until += Duration::from_millis(66);
                pace(sleep_until);
            }
        }
        Kind::Scroll => {
            let (w, h) = (sw.min(1280), sh.min(720));
            // A texture twice the visible height, filled with pseudo-text: rows of short
            // dark runs on white, so scrolling it looks like a document.
            let stride = w * 4;
            let mut tex = vec![255u8; stride * h * 2];
            let mut rng = 0x1234_5678u32;
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 17;
                rng ^= rng << 5;
                rng
            };
            for line in (0..h * 2).step_by(18) {
                let mut x = 20usize;
                while x + 40 < w {
                    let run = 6 + (next() % 40) as usize;
                    for row in line..(line + 11).min(h * 2) {
                        for px in tex[row * stride + x * 4..row * stride + (x + run).min(w) * 4]
                            .chunks_mut(4)
                        {
                            px.copy_from_slice(&[30, 30, 30, 255]);
                        }
                    }
                    x += run + 6 + (next() % 10) as usize;
                }
            }
            let mut offset = 0usize;
            const CHUNK: usize = 64;
            while !stop.load(Relaxed) {
                for y0 in (0..h).step_by(CHUNK) {
                    let rows = CHUNK.min(h - y0);
                    let src = (offset + y0) * stride;
                    conn.put_image(
                        ImageFormat::Z_PIXMAP,
                        root,
                        gc,
                        w as u16,
                        rows as u16,
                        0,
                        y0 as i16,
                        0,
                        depth,
                        &tex[src..src + rows * stride],
                    )?;
                }
                conn.flush()?;
                conn.get_input_focus()?.reply()?;
                offset = (offset + 6) % h;
                sleep_until += Duration::from_nanos(1_000_000_000 / 60);
                pace(sleep_until);
            }
        }
    }
    Ok(())
}

/// Sleep until `t`; if already late, carry on (the deadline does not drift forward).
fn pace(t: Instant) {
    if let Some(d) = t.checked_duration_since(Instant::now()) {
        std::thread::sleep(d);
    }
}
