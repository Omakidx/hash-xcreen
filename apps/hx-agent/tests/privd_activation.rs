//! Socket activation with the real `systemd-socket-activate` (the audited `unsafe` adoption of
//! descriptor 3 in `privd::activation`). Skipped where the tool is not installed.
//!
//! The test re-runs its own binary as the activated child: `systemd-socket-activate` creates and
//! listens on the socket, and on the first connection starts the child with `LISTEN_PID` and
//! `LISTEN_FDS=1`; the child adopts the descriptor, checks it, accepts the connection, reads a
//! line and writes its verdict to a file.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hx_agent::privd::activation;

/// The activated child. A plain test that does nothing unless the parent started it.
#[test]
fn activated_child() {
    let (Ok(out), Ok(sock)) = (std::env::var("HX_ACT_OUT"), std::env::var("HX_ACT_SOCK")) else {
        return;
    };
    let verdict = (|| -> Result<String, String> {
        let l = activation::from_env(Path::new(&sock)).map_err(|e| e.to_string())?;
        // A second adoption in the same process is refused.
        if activation::from_env(Path::new(&sock)).is_ok() {
            return Err("a second adoption was accepted".into());
        }
        l.set_nonblocking(false).map_err(|e| e.to_string())?;
        let (mut s, _) = l.accept().map_err(|e| e.to_string())?;
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).map_err(|e| e.to_string())?;
        s.write_all(b"pong").map_err(|e| e.to_string())?;
        Ok(format!(
            "adopted and served: {}",
            String::from_utf8_lossy(&buf)
        ))
    })();
    std::fs::write(&out, verdict.unwrap_or_else(|e| format!("FAILED: {e}"))).unwrap();
}

#[test]
fn the_activated_descriptor_is_adopted_checked_and_served() {
    let Ok(tool) = Command::new("systemd-socket-activate")
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    else {
        eprintln!("systemd-socket-activate is not installed: skipping");
        return;
    };
    assert!(tool.success());
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("act.sock");
    let out = dir.path().join("verdict");
    let exe = std::env::current_exe().unwrap();
    let mut parent = Command::new("systemd-socket-activate")
        .arg("-l")
        .arg(&sock)
        .arg("-E")
        .arg(format!("HX_ACT_OUT={}", out.display()))
        .arg("-E")
        .arg(format!("HX_ACT_SOCK={}", sock.display()))
        .arg(&exe)
        .args(["--exact", "activated_child", "--nocapture"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Wait for the listening socket, then connect: that starts the child.
    let started = Instant::now();
    while !sock.exists() {
        assert!(started.elapsed() < Duration::from_secs(10), "no socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut c = UnixStream::connect(&sock).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.write_all(b"hello").unwrap();
    let mut reply = [0u8; 4];
    c.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"pong");
    // The child writes its verdict after it replied.
    let waited = Instant::now();
    let verdict = loop {
        if let Ok(v) = std::fs::read_to_string(&out) {
            break v;
        }
        assert!(waited.elapsed() < Duration::from_secs(10), "no verdict");
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = parent.kill();
    let _ = parent.wait();
    assert!(verdict.starts_with("adopted and served"), "{verdict}");
}
