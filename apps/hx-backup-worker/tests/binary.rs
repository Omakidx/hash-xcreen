//! The real `hx-backup-worker` binary: role dispatch, and whole jobs with the enforcing sandbox.
//!
//! The jobs run the binary under `unshare -Ur` (root with capabilities inside a user namespace, no
//! privilege on the host), so that the capability drop, the seccomp allowlist in `Enforce` mode (a
//! missing syscall kills the process) and numeric-owner restore are all real. The test plays privd
//! with the fake of `common`. Skipped, with a message, where user namespaces are disabled.

mod common;

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::*;
use hx_backup_worker::role::{EXIT_DRIVE_CLIENT, EXIT_ROLE};

/// The binary under test: the one Cargo built, or `HX_WORKER_BIN` (CI runs this file against the
/// static musl build).
fn bin() -> String {
    std::env::var("HX_WORKER_BIN")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_hx-backup-worker").to_owned())
}

#[test]
fn the_role_fails_closed_and_the_drive_role_fails_closed_without_its_client() {
    let run = |role: Option<&str>, args: &[&str]| {
        let mut c = Command::new(bin());
        c.args(args).stdin(Stdio::null());
        c.env_remove("HX_BACKUP_ROLE");
        if let Some(r) = role {
            c.env("HX_BACKUP_ROLE", r);
        }
        c.output().unwrap()
    };
    assert_eq!(run(Some("bogus"), &[]).status.code(), Some(EXIT_ROLE));
    assert_eq!(run(Some(""), &[]).status.code(), Some(EXIT_ROLE));
    assert_eq!(run(None, &["--version"]).status.code(), Some(EXIT_ROLE));
    // The drive role without its OAuth client file serves nothing (ipc.md §29 a).
    let d = Command::new(bin())
        .env("HX_BACKUP_ROLE", "drive")
        .env("HX_WORKER_DRIVE_CLIENT", "/nonexistent/drive-client.json")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(d.status.code(), Some(EXIT_DRIVE_CLIENT));
    assert!(String::from_utf8_lossy(&d.stderr).contains("OAuth client file"));
}

fn userns_works() -> bool {
    Command::new("unshare")
        .args(["-Ur", "true"])
        .status()
        .is_ok_and(|s| s.success())
}

fn spawn(root: &Path) -> (Child, UnixStream) {
    let run_dir = root.join("run");
    let mut cmd = Command::new("unshare");
    cmd.args(["-Ur", "--"]);
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if let Some(log) = std::env::var_os("HX_TEST_STRACE")
        && n == 1
    {
        cmd.args(["strace", "-f", "-o"]).arg(log).arg("--");
    }
    let child = cmd
        .arg(bin())
        .env_remove("HX_BACKUP_ROLE")
        .env("HX_WORKER_RUN_DIR", &run_dir)
        .env("HX_WORKER_SRC", root.join("src"))
        .env("HX_WORKER_DST", root.join("dst"))
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let sock = run_dir.join("repo.sock");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match UnixStream::connect(&sock) {
            Ok(s) => return (child, s),
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("the worker never listened: {e}"),
        }
    }
}

fn job(root: &Path, store: &SharedStore, j: JobSpec) -> Outcome {
    let (mut child, stream) = spawn(root);
    let out = Fake::new(stream, j.job, j.secrets, store.clone(), Behavior::default()).run();
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0), "worker status {status:?}; {out:?}");
    assert!(
        !root.join("run/repo.sock").exists(),
        "the listener's socket is removed after the one connection"
    );
    assert!(
        out.worker_violations.is_empty(),
        "{:?}",
        out.worker_violations
    );
    assert!(out.denied.is_empty(), "{:?}", out.denied);
    assert!(out.bye);
    let r = out.result.as_ref().expect("JobResult");
    assert!(r.ok, "job failed: {:?}", pb_err(r.error));
    out
}

fn pb_err(e: i32) -> Option<hx_ipc::repo::pb::WorkerError> {
    hx_ipc::repo::pb::WorkerError::try_from(e).ok()
}

#[test]
fn whole_jobs_run_under_the_enforcing_sandbox() {
    if !userns_works() {
        eprintln!("skipped: `unshare -Ur` does not work here (user namespaces disabled)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    make_tree(&root.join("src"));
    let store = new_store();

    job(root, &store, init_job());
    let b = job(root, &store, backup_job(&[], &["nightly"]));
    let id = b.result.unwrap().snapshot_id;
    let s = job(root, &store, snapshots_job());
    assert_eq!(s.result.unwrap().snapshots.len(), 1);
    job(root, &store, check_job(100));
    job(root, &store, restore_plan_job(&id));
    // numeric owners are restored for real (CAP_CHOWN kept, inside the namespace)
    job(root, &store, restore_job(&id));
    assert_same_tree(&root.join("src"), &root.join("dst"));
    job(root, &store, forget_job(&[]));
}
