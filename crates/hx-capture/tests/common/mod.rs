//! Test helper: a private Xvfb on a free display number.
//!
//! Tests skip (with a message) when Xvfb is not installed, unless `HX_REQUIRE_XVFB` is set,
//! which CI does so a missing package fails the build instead of silently skipping.
#![allow(dead_code)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt as _, CreateGCAux, Rectangle};
use x11rb::rust_connection::RustConnection;

pub struct Xvfb {
    child: Child,
    pub display: String,
}

impl Xvfb {
    /// Start Xvfb with a 24-bit screen. `None` when it is not installed and not required.
    pub fn start(width: u32, height: u32) -> Option<Xvfb> {
        let spawned = Command::new("Xvfb")
            .args([
                "-displayfd",
                "1",
                "-nolisten",
                "tcp",
                "-noreset",
                "-screen",
                "0",
            ])
            .arg(format!("{width}x{height}x24"))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match spawned {
            Ok(c) => c,
            Err(e) => {
                assert!(
                    std::env::var_os("HX_REQUIRE_XVFB").is_none(),
                    "Xvfb is required (HX_REQUIRE_XVFB is set) but cannot start: {e}"
                );
                eprintln!("skipping: Xvfb not available ({e})");
                return None;
            }
        };
        let mut line = String::new();
        let out = child.stdout.take().expect("piped stdout");
        BufReader::new(out)
            .read_line(&mut line)
            .expect("read Xvfb display number");
        let n: u32 = line.trim().parse().expect("Xvfb printed a display number");
        Some(Xvfb {
            child,
            display: format!(":{n}"),
        })
    }
}

impl Xvfb {
    /// Kill the server while clients are connected.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Xvfb {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Fill a rectangle of the root window with `rgb` (0xRRGGBB) over a second connection.
pub fn fill_root(display: &str, rect: (i16, i16, u16, u16), rgb: u32) {
    let (conn, n) = RustConnection::connect(Some(display)).expect("connect");
    let root = conn.setup().roots[n].root;
    let gc = conn.generate_id().expect("id");
    conn.create_gc(gc, root, &CreateGCAux::new().foreground(rgb))
        .expect("gc");
    conn.poly_fill_rectangle(
        root,
        gc,
        &[Rectangle {
            x: rect.0,
            y: rect.1,
            width: rect.2,
            height: rect.3,
        }],
    )
    .expect("fill");
    conn.flush().expect("flush");
    // Make sure the server processed it before returning.
    conn.get_input_focus()
        .expect("sync")
        .reply()
        .expect("reply");
}
