//! The hidden prompt, on a real pseudo-terminal: echo is off while a secret is typed, the secret
//! is not echoed back, the terminal settings are restored (also after Ctrl-C and an over-long
//! answer), and a confirmation is visible.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use hx_agent::cli::error::exit;
use hx_agent::cli::{Prompter, TtyPrompter};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{LocalModes, tcgetattr};

struct Pty {
    master: File,
    /// The slave, kept open so the pty stays alive and its settings can be inspected.
    probe: File,
    path: PathBuf,
}

fn pty() -> Pty {
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("openpt");
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let name = ptsname(&master, Vec::new()).unwrap();
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(name.to_bytes()));
    let probe = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(rustix::fs::OFlags::NOCTTY.bits() as i32)
        .open(&path)
        .unwrap();
    Pty {
        master: File::from(master),
        probe,
        path,
    }
}

impl Pty {
    fn echo(&self) -> bool {
        tcgetattr(&self.probe)
            .unwrap()
            .local_modes
            .contains(LocalModes::ECHO)
    }

    fn modes(&self) -> LocalModes {
        tcgetattr(&self.probe).unwrap().local_modes
    }

    /// Reads from the master until `needle` appeared (or a few seconds passed).
    fn read_until(&mut self, needle: &str) -> String {
        let mut got = Vec::new();
        let end = Instant::now() + Duration::from_secs(5);
        let mut buf = [0u8; 256];
        while Instant::now() < end && !String::from_utf8_lossy(&got).contains(needle) {
            let n = self.master.read(&mut buf).expect("read the master");
            got.extend_from_slice(&buf[..n]);
        }
        String::from_utf8_lossy(&got).into_owned()
    }

    fn wait_until_echo_is(&self, want: bool) {
        let end = Instant::now() + Duration::from_secs(5);
        while self.echo() != want {
            assert!(Instant::now() < end, "echo never became {want}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[test]
fn a_secret_is_read_with_echo_off_and_the_terminal_is_restored() {
    let mut p = pty();
    let before = p.modes();
    assert!(before.contains(LocalModes::ECHO) && before.contains(LocalModes::ISIG));
    let path = p.path.clone();
    let t = std::thread::spawn(move || TtyPrompter::at(path).secret("pw: ", 32));
    let shown = p.read_until("pw: ");
    assert!(shown.contains("pw: "), "{shown:?}");
    p.wait_until_echo_is(false);
    let during = p.modes();
    assert!(
        !during.contains(LocalModes::ISIG),
        "Ctrl-C must not kill the process with echo off"
    );
    assert!(during.contains(LocalModes::ICANON), "line editing stays on");
    p.master.write_all(b"hunter2-secret\n").unwrap();
    let got = t.join().unwrap().unwrap();
    assert_eq!(&got[..], b"hunter2-secret");
    // What the terminal showed after the prompt: a newline, not the secret.
    let after = p.read_until("\n");
    assert!(
        !after.contains("hunter2"),
        "the secret was echoed: {after:?}"
    );
    assert_eq!(p.modes(), before, "the settings are restored");
}

#[test]
fn ctrl_c_aborts_the_prompt_and_restores_the_terminal() {
    let mut p = pty();
    let before = p.modes();
    let path = p.path.clone();
    let t = std::thread::spawn(move || TtyPrompter::at(path).secret("pw: ", 32));
    p.read_until("pw: ");
    p.wait_until_echo_is(false);
    p.master.write_all(b"ab\x03\n").unwrap();
    let err = t.join().unwrap().unwrap_err();
    assert_eq!(err.exit_code(), exit::DECLINED, "{err}");
    assert_eq!(p.modes(), before);
}

#[test]
fn an_overlong_secret_is_refused_without_keeping_it() {
    let mut p = pty();
    let before = p.modes();
    let path = p.path.clone();
    let t = std::thread::spawn(move || TtyPrompter::at(path).secret("pw: ", 4));
    p.read_until("pw: ");
    p.wait_until_echo_is(false);
    p.master.write_all(b"123456789\n").unwrap();
    let err = t.join().unwrap().unwrap_err();
    assert_eq!(err.exit_code(), exit::USAGE, "{err}");
    assert_eq!(p.modes(), before);
}

#[test]
fn a_confirmation_is_a_visible_line() {
    let mut p = pty();
    let path = p.path.clone();
    let t = std::thread::spawn(move || TtyPrompter::at(path).line("Type 'yes': "));
    p.read_until("Type 'yes': ");
    assert!(p.echo(), "a confirmation is typed with echo on");
    p.master.write_all(b"  yes \n").unwrap();
    assert_eq!(t.join().unwrap().unwrap(), "yes");
}

#[test]
fn without_a_terminal_there_is_no_answer() {
    let missing = std::env::temp_dir().join("hx-agent-no-such-tty");
    let err = TtyPrompter::at(&missing).secret("pw: ", 8).unwrap_err();
    assert_eq!(err.exit_code(), exit::DECLINED);
    assert!(err.message().contains("no terminal"), "{err}");
    let err = TtyPrompter::at(&missing).line("q: ").unwrap_err();
    assert_eq!(err.exit_code(), exit::DECLINED);
}

#[test]
fn n3_quit_and_suspend_characters_abort_instead_of_entering_the_secret() {
    for byte in [0x1c_u8, 0x1a] {
        let mut p = pty();
        let before = p.modes();
        let path = p.path.clone();
        let t = std::thread::spawn(move || TtyPrompter::at(path).secret("pw: ", 32));
        p.read_until("pw: ");
        p.wait_until_echo_is(false);
        p.master.write_all(&[b'a', byte, b'b', b'\n']).unwrap();
        let err = t.join().unwrap().unwrap_err();
        assert_eq!(err.exit_code(), exit::DECLINED, "{byte:#x}: {err}");
        assert_eq!(p.modes(), before);
    }
}

/// The bits of `SigBlk` in /proc for one thread.
fn blocked_signals(task: &str) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{task}/status")).unwrap();
    let line = status.lines().find(|l| l.starts_with("SigBlk:")).unwrap();
    u64::from_str_radix(line["SigBlk:".len()..].trim(), 16).unwrap()
}

#[test]
fn n3_termination_signals_are_blocked_while_the_prompt_has_echo_off_and_released_after() {
    let mut p = pty();
    let path = p.path.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let t = std::thread::spawn(move || {
        // "<pid>/task/<tid>" of this thread, to read its signal mask from the outside.
        let me = std::fs::read_link("/proc/thread-self").unwrap();
        tx.send(me.to_string_lossy().into_owned()).unwrap();
        let r = TtyPrompter::at(path).secret("pw: ", 32);
        (r, blocked_signals("thread-self"))
    });
    let task = rx.recv().unwrap();
    p.read_until("pw: ");
    p.wait_until_echo_is(false);
    let during = blocked_signals(&task);
    // SIGHUP 1, SIGINT 2, SIGQUIT 3, SIGTERM 15, SIGTSTP 20: bit (signal - 1).
    for sig in [1u32, 2, 3, 15, 20] {
        assert!(
            during & (1 << (sig - 1)) != 0,
            "signal {sig} is not blocked: {during:#x}"
        );
    }
    p.master.write_all(b"x\n").unwrap();
    let (r, after) = t.join().unwrap();
    r.unwrap();
    assert_eq!(after & 0x8_400F, 0, "the block is lifted again: {after:#x}");
}
