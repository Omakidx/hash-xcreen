//! The capability drop and the seccomp allowlist really apply (ipc.md §24).
//!
//! A sandbox cannot be installed in the test harness itself, so the test re-runs itself in a child
//! (`probe_child`), inside a new user namespace made with `unshare -Ur` (the child is root with a full
//! capability set there, with no privilege on the host: no sudo needed). The child hardens itself for
//! a job kind and prints what it observes; the parent checks the lines. Where `unshare -Ur` does not
//! work (unprivileged user namespaces disabled) the tests say so and pass.
//!
//! The child uses [`Mode::Errno`] so that a refused call can be seen; the binary only ever uses
//! `Enforce`, which `tests/binary.rs` runs for real.

use std::process::Command;

use hx_backup_worker::sandbox::{self, Cap, Mode, capabilities_for};
use hx_ipc::repo::pb::JobKind;

const PROBE_ENV: &str = "HX_SANDBOX_PROBE";

fn kind_name(k: JobKind) -> &'static str {
    match k {
        JobKind::Backup => "backup",
        JobKind::Restore => "restore",
        JobKind::Snapshots => "snapshots",
        _ => unreachable!(),
    }
}

fn kind_of(name: &str) -> JobKind {
    match name {
        "backup" => JobKind::Backup,
        "restore" => JobKind::Restore,
        "snapshots" => JobKind::Snapshots,
        _ => panic!("unknown kind"),
    }
}

fn userns_works() -> bool {
    Command::new("unshare")
        .args(["-Ur", "true"])
        .status()
        .is_ok_and(|s| s.success())
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// `syscall(nr, ...)` that returns the errno (0 on success).
fn try_syscall(nr: libc::c_long, a: [libc::c_long; 4]) -> i32 {
    // SAFETY: only called with arguments that are valid or null for the calls below; the point is
    // to see whether the kernel (the filter) lets the call through.
    let r = unsafe { libc::syscall(nr, a[0], a[1], a[2], a[3]) };
    if r < 0 { errno() } else { 0 }
}

/// The child: harden for the kind named in the environment, then print what happens.
#[test]
fn probe_child() {
    let Ok(name) = std::env::var(PROBE_ENV) else {
        return; // an ordinary run of the test suite
    };
    let kind = kind_of(&name);
    let tmp = std::env::var("HX_PROBE_DIR").unwrap();

    // threads started before the filter must also be covered (TSYNC): one is parked here
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let parked = std::thread::spawn(move || {
        let _ = stop_rx.recv();
        // after the filter: a forbidden call from this older thread is refused as well
        let c = std::ffi::CString::new("127.0.0.1").unwrap();
        let _ = c;
        try_syscall(
            libc::SYS_socket,
            [libc::AF_INET as _, libc::SOCK_STREAM as _, 0, 0],
        )
    });
    std::thread::sleep(std::time::Duration::from_millis(50));

    let before = sandbox::capability_sets().unwrap();
    println!("RESULT caps_before_nonzero={}", before.permitted != 0);
    sandbox::harden(kind, Mode::Errno).expect("harden");

    let after = sandbox::capability_sets().unwrap();
    let want: u64 = capabilities_for(kind)
        .iter()
        .fold(0, |m, c| m | 1u64 << (*c as u8));
    println!("RESULT cap_eff_ok={}", after.effective == want);
    println!("RESULT cap_perm_ok={}", after.permitted == want);
    println!("RESULT cap_inh_zero={}", after.inheritable == 0);
    println!("RESULT caps_before_nonzero={}", before.permitted != 0);
    let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .map(|v| v.trim().to_owned())
            .unwrap()
    };
    println!(
        "RESULT bounding_gone={}",
        u64::from_str_radix(&field("CapBnd:"), 16).unwrap() == want
    );
    println!("RESULT no_new_privs={}", field("NoNewPrivs:") == "1");

    // forbidden calls: refused with EPERM from the filter
    let e = |what: &str, code: i32| println!("RESULT {what}={code}");
    e(
        "socket",
        try_syscall(
            libc::SYS_socket,
            [libc::AF_UNIX as _, libc::SOCK_STREAM as _, 0, 0],
        ),
    );
    e(
        "socket_inet",
        try_syscall(
            libc::SYS_socket,
            [libc::AF_INET as _, libc::SOCK_STREAM as _, 0, 0],
        ),
    );
    e("connect", try_syscall(libc::SYS_connect, [3, 0, 0, 0]));
    e("bind", try_syscall(libc::SYS_bind, [3, 0, 0, 0]));
    e("execve", try_syscall(libc::SYS_execve, [0, 0, 0, 0]));
    e(
        "ptrace",
        try_syscall(libc::SYS_ptrace, [libc::PTRACE_TRACEME as _, 0, 0, 0]),
    );
    e("mount", try_syscall(libc::SYS_mount, [0, 0, 0, 0]));
    e(
        "unshare",
        try_syscall(libc::SYS_unshare, [libc::CLONE_NEWNET as _, 0, 0, 0]),
    );
    e("kill", try_syscall(libc::SYS_kill, [1, 0, 0, 0]));
    e(
        "fork_clone",
        try_syscall(libc::SYS_clone, [libc::SIGCHLD as _, 0, 0, 0]),
    );
    e(
        "setdumpable_1",
        try_syscall(libc::SYS_prctl, [libc::PR_SET_DUMPABLE as _, 1, 0, 0]),
    );
    e("parked_thread_socket", {
        stop_tx.send(()).unwrap();
        parked.join().unwrap()
    });

    // file writes: only RESTORE may create files, and set extended attributes
    let path = format!("{tmp}/probe-{name}\0");
    // SAFETY: a valid NUL-terminated path, plain flags.
    let fd = unsafe {
        libc::open(
            path.as_ptr().cast(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC,
            0o600,
        )
    };
    let create_errno = if fd < 0 { errno() } else { 0 };
    println!("RESULT create_file={create_errno}");
    if fd >= 0 {
        // SAFETY: a descriptor we own.
        unsafe { libc::close(fd) };
    }
    let existing = format!("{tmp}/existing\0");
    let xname = b"user.hx\0";
    let xval = b"1";
    e(
        "setxattr",
        try_syscall(
            libc::SYS_setxattr,
            [
                existing.as_ptr() as libc::c_long,
                xname.as_ptr() as libc::c_long,
                xval.as_ptr() as libc::c_long,
                1,
            ],
        ),
    );
    e(
        "unlink",
        try_syscall(
            libc::SYS_unlinkat,
            [libc::AT_FDCWD as _, existing.as_ptr() as libc::c_long, 0, 0],
        ),
    );
    // reading still works
    println!(
        "RESULT read_ok={}",
        std::fs::read_to_string("/proc/self/status").is_ok()
    );
    // and a new thread can be started (clone with thread flags; clone3 answers ENOSYS)
    println!(
        "RESULT thread_ok={}",
        std::thread::spawn(|| 7).join().ok() == Some(7)
    );
}

fn run_probe(kind: JobKind) -> Option<std::collections::HashMap<String, String>> {
    if !userns_works() {
        eprintln!("skipped: `unshare -Ur` does not work here (user namespaces disabled)");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("existing"), b"x").unwrap();
    let exe = std::env::current_exe().unwrap();
    let out = Command::new("unshare")
        .args(["-Ur", "--"])
        .arg(exe)
        .args(["--exact", "probe_child", "--nocapture", "--test-threads=1"])
        .env(PROBE_ENV, kind_name(kind))
        .env("HX_PROBE_DIR", dir.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "the probe child failed ({:?}): {stdout}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    Some(
        stdout
            .lines()
            .filter_map(|l| l.strip_prefix("RESULT "))
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
    )
}

const EPERM: &str = "1";

fn expect(r: &std::collections::HashMap<String, String>, key: &str, want: &str) {
    assert_eq!(
        r.get(key).map(String::as_str),
        Some(want),
        "{key}: all results {r:?}"
    );
}

fn common_expectations(r: &std::collections::HashMap<String, String>) {
    for k in [
        "cap_eff_ok",
        "cap_perm_ok",
        "cap_inh_zero",
        "bounding_gone",
        "no_new_privs",
        "read_ok",
        "thread_ok",
    ] {
        expect(r, k, "true");
    }
    expect(r, "caps_before_nonzero", "true");
    for k in [
        "socket",
        "socket_inet",
        "connect",
        "bind",
        "execve",
        "ptrace",
        "mount",
        "unshare",
        "kill",
        "fork_clone",
        "setdumpable_1",
        "parked_thread_socket",
    ] {
        expect(r, k, EPERM);
    }
}

#[test]
fn a_backup_worker_keeps_one_capability_and_cannot_write_or_reach_a_network() {
    let Some(r) = run_probe(JobKind::Backup) else {
        return;
    };
    common_expectations(&r);
    expect(&r, "create_file", EPERM);
    expect(&r, "setxattr", EPERM);
    expect(&r, "unlink", EPERM);
}

#[test]
fn a_repository_only_worker_keeps_no_capability_and_cannot_write() {
    let Some(r) = run_probe(JobKind::Snapshots) else {
        return;
    };
    common_expectations(&r);
    expect(&r, "create_file", EPERM);
    expect(&r, "setxattr", EPERM);
}

#[test]
fn a_restore_worker_keeps_six_capabilities_and_may_write_but_still_not_reach_a_network() {
    let Some(r) = run_probe(JobKind::Restore) else {
        return;
    };
    common_expectations(&r);
    // allowed by the filter: file creation works, the xattr call is not refused by seccomp (the
    // file system may not support it: anything but the filter's EPERM)
    expect(&r, "create_file", "0");
    assert_ne!(r["setxattr"], EPERM, "{r:?}");
    expect(&r, "unlink", "0");
}

#[test]
fn the_kinds_and_their_capabilities_are_the_contracts() {
    assert_eq!(capabilities_for(JobKind::Backup), &[Cap::DacReadSearch]);
    assert_eq!(capabilities_for(JobKind::Restore).len(), 6);
    assert!(capabilities_for(JobKind::ForgetPrune).is_empty());
}
