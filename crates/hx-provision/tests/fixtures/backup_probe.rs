//! Test fixture for `tests/incus_real_backup.rs`: a statically linked, std-only program that plays
//! the part of `hx-backup-worker` (as the helper's PID 1) and of the data generator and checker
//! inside the source and target containers. It is compiled by the test with
//! `rustc -C target-feature=+crt-static` (never part of the workspace build) and has no
//! dependencies.
//!
//! Modes (argv[1]):
//!
//! - `make <dir>`: create the probe tree below `<dir>` (ids 1234:4321 and 1000:1000, a v2 file
//!   capability, a user extended attribute, a fifo);
//! - `dump <dir> <root> [out]`: print (or write to `out`, for a container that has no shell to
//!   capture stdout) one line per probe entry, one for `<root>/etc/shadow` and the user
//!   namespace's `uid_map`;
//! - no argument (the helper's PID 1, or `/sbin/init` of a restored target): with `/src` present
//!   it is the backup worker and reports `dump` of `/src` plus the read-only and network checks,
//!   with `/dst` present it is the restore worker and writes the probe tree and the mount-point
//!   directories through `/dst`, with neither it idles (a restored target).
//!
//! Both workers serve the repository link the way ipc.md 24 describes the worker's end: create
//! `/run/hx-worker` (0700) and `repo.sock`, accept exactly one connection, read one line, write
//! the report, close and exit.

use std::ffi::{CString, c_char, c_int, c_void};
use std::fmt::Write as _;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::time::Duration;

unsafe extern "C" {
    fn setxattr(
        path: *const c_char,
        name: *const c_char,
        value: *const c_void,
        size: usize,
        flags: c_int,
    ) -> c_int;
    fn lgetxattr(
        path: *const c_char,
        name: *const c_char,
        value: *mut c_void,
        size: usize,
    ) -> isize;
    fn lchown(path: *const c_char, uid: u32, gid: u32) -> c_int;
    fn mkfifo(path: *const c_char, mode: u32) -> c_int;
}

const USER_XATTR: &str = "user.hx.probe";
const USER_XATTR_VALUE: &[u8] = b"hx-probe-value";
const CAP_XATTR: &str = "security.capability";
/// VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE, permitted CAP_NET_RAW (13), nothing else.
const CAP_V2: [u8; 20] = [
    0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fn c(p: &Path) -> CString {
    CString::new(p.as_os_str().as_bytes()).expect("no NUL in a path")
}

fn cs(s: &str) -> CString {
    CString::new(s).expect("no NUL")
}

fn errno() -> std::io::Error {
    std::io::Error::last_os_error()
}

fn chown(p: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    // SAFETY: a valid NUL-terminated path.
    if unsafe { lchown(c(p).as_ptr(), uid, gid) } == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

fn set_xattr(p: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
    // SAFETY: valid NUL-terminated strings and a buffer of `value.len()` bytes.
    let r = unsafe {
        setxattr(
            c(p).as_ptr(),
            cs(name).as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if r == 0 { Ok(()) } else { Err(errno()) }
}

fn get_xattr(p: &Path, name: &str) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 256];
    // SAFETY: as above, with a writable buffer of `buf.len()` bytes.
    let n = unsafe {
        lgetxattr(
            c(p).as_ptr(),
            cs(name).as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    (n >= 0).then(|| {
        buf.truncate(n as usize);
        buf
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn make(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let a = dir.join("a");
    fs::write(&a, b"a")?;
    chown(&a, 1234, 4321)?;
    fs::set_permissions(&a, fs::Permissions::from_mode(0o640))?;
    let b = dir.join("b");
    fs::write(&b, b"b")?;
    chown(&b, 1000, 1000)?;
    fs::set_permissions(&b, fs::Permissions::from_mode(0o644))?;
    // chown clears file capabilities, so set them last.
    let cap = dir.join("cap");
    fs::write(&cap, b"#!/bin/true\n")?;
    chown(&cap, 1234, 4321)?;
    fs::set_permissions(&cap, fs::Permissions::from_mode(0o755))?;
    set_xattr(&cap, CAP_XATTR, &CAP_V2)?;
    let ux = dir.join("ux");
    fs::write(&ux, b"x")?;
    chown(&ux, 1000, 1000)?;
    set_xattr(&ux, USER_XATTR, USER_XATTR_VALUE)?;
    let fifo = dir.join("fifo");
    // SAFETY: a valid NUL-terminated path.
    if unsafe { mkfifo(c(&fifo).as_ptr(), 0o640) } != 0 {
        return Err(errno());
    }
    chown(&fifo, 1000, 1000)?;
    Ok(())
}

fn dump(dir: &Path, root: &Path) -> String {
    let mut out = String::new();
    for name in ["a", "b", "cap", "ux", "fifo"] {
        let p = dir.join(name);
        match fs::symlink_metadata(&p) {
            Ok(m) => {
                let kind = if m.file_type().is_fifo() {
                    "fifo"
                } else if m.is_file() {
                    "file"
                } else {
                    "other"
                };
                let cap = get_xattr(&p, CAP_XATTR).map_or("-".to_string(), |v| hex(&v));
                let ux = get_xattr(&p, USER_XATTR).map_or("-".to_string(), |v| {
                    String::from_utf8_lossy(&v).into_owned()
                });
                let _ = writeln!(
                    out,
                    "entry={name} uid={} gid={} mode={:04o} kind={kind} cap={cap} xattr={ux}",
                    m.uid(),
                    m.gid(),
                    m.mode() & 0o7777
                );
            }
            Err(e) => {
                let _ = writeln!(out, "entry={name} error={e}");
            }
        }
    }
    let shadow = root.join("etc/shadow");
    match fs::metadata(&shadow) {
        Ok(m) => {
            let readable = fs::read(&shadow).map(|d| d.len()).ok();
            let _ = writeln!(
                out,
                "shadow uid={} gid={} mode={:04o} readable={}",
                m.uid(),
                m.gid(),
                m.mode() & 0o7777,
                readable.map_or("no".to_string(), |n| format!("yes len={n}"))
            );
        }
        Err(e) => {
            let _ = writeln!(out, "shadow error={e}");
        }
    }
    out
}

fn net_ifaces() -> String {
    let mut v: Vec<String> = fs::read_dir("/sys/class/net")
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_else(|e| vec![format!("error:{e}")]);
    v.sort();
    v.join(",")
}

fn uid_map() -> String {
    fs::read_to_string("/proc/self/uid_map")
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn backup_report() -> String {
    let mut out = String::from("mode=backup\n");
    out += &dump(Path::new("/src/probe"), Path::new("/src"));
    // A write through the read-only mount must give EROFS (30).
    let w = fs::write("/src/probe/new", b"x");
    let _ = writeln!(
        out,
        "write errno={}",
        w.err()
            .and_then(|e| e.raw_os_error())
            .map_or("none".to_string(), |n| n.to_string())
    );
    let _ = writeln!(out, "ifaces={}", net_ifaces());
    let _ = writeln!(out, "uid_map={}", uid_map());
    out
}

fn restore_report() -> String {
    let mut out = String::from("mode=restore\n");
    let r = (|| -> std::io::Result<()> {
        make(Path::new("/dst/probe"))?;
        for d in ["dev", "proc", "sys", "run", "tmp", "sbin", "etc"] {
            fs::create_dir_all(Path::new("/dst").join(d))?;
        }
        // The restored target needs an init to start: use this very binary.
        fs::copy("/sbin/init", "/dst/sbin/init")?;
        fs::set_permissions("/dst/sbin/init", fs::Permissions::from_mode(0o755))?;
        Ok(())
    })();
    let _ = writeln!(
        out,
        "restore={}",
        r.map_or_else(|e| format!("error: {e}"), |()| "ok".to_string())
    );
    let _ = writeln!(out, "ifaces={}", net_ifaces());
    out
}

fn serve(report: String) -> std::process::ExitCode {
    // A stuck helper must not outlive the test.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(120));
        std::process::exit(2);
    });
    let setup = (|| -> std::io::Result<UnixListener> {
        fs::create_dir_all("/run/hx-worker")?;
        fs::set_permissions("/run/hx-worker", fs::Permissions::from_mode(0o700))?;
        UnixListener::bind("/run/hx-worker/repo.sock")
    })();
    let listener = match setup {
        Ok(l) => l,
        Err(e) => {
            eprintln!("listener: {e}");
            return std::process::ExitCode::from(3);
        }
    };
    let Ok((mut conn, _)) = listener.accept() else {
        return std::process::ExitCode::from(4);
    };
    drop(listener);
    let mut line = String::new();
    let _ = BufReader::new(&conn).read_line(&mut line);
    let reply = format!("{report}got={}\n", line.trim_end());
    let _ = conn.write_all(reply.as_bytes());
    let _ = conn.flush();
    std::process::ExitCode::SUCCESS
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("make") => match make(Path::new(&args[2])) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("make: {e}");
                std::process::ExitCode::from(1)
            }
        },
        Some("dump") => {
            let mut text = dump(Path::new(&args[2]), Path::new(&args[3]));
            let _ = writeln!(text, "uid_map={}", uid_map());
            match args.get(4) {
                Some(out) => {
                    if let Err(e) = fs::write(out, text) {
                        eprintln!("dump: {e}");
                        return std::process::ExitCode::from(1);
                    }
                }
                None => print!("{text}"),
            }
            std::process::ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown mode {other}");
            std::process::ExitCode::from(1)
        }
        None => {
            if Path::new("/src").is_dir() {
                serve(backup_report())
            } else if Path::new("/dst").is_dir() {
                serve(restore_report())
            } else {
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            }
        }
    }
}
