//! Crash recovery and the cleanup before `DestroyDesktop` and `Uninstall` (ipc.md section 35):
//! first through the runner with a fake host, then through the daemon over a fake Incus, so that
//! the hooks in the two command paths and the start-up call are exercised for real.

mod backup_common;

use std::os::unix::net::UnixListener;
use std::sync::Arc;

use backup_common::*;
use hx_agent::privd::backup::runner::StartError;
use hx_agent::privd::backup::slot::{BackupDirs, FORMAT, JobRecord, ResumeRecord, kind_name};
use hx_agent::privd::backup::spec::JobSpec;
use hx_agent::privd::backup::{Failure, JobState};
use hx_agent::privd::daemon::Ctx;
use hx_agent::privd::runner::Tool;
use hx_agent::privd::testing::{FakeInstance, Harness, request};
use hx_ipc::privd::pb::{self, Role, request::Command, response::Result as R};
use hx_ipc::repo::pb::JobKind;
use hx_provision::incus::JobId;

const GW: u32 = 4_242;

fn job(n: u8) -> JobId {
    JobId::from_bytes([n; 16]).unwrap()
}

fn leave_socket(dir: &std::path::Path, name: &str) {
    // A socket file that nobody listens on, as Incus leaves behind.
    drop(UnixListener::bind(dir.join(name)).unwrap());
}

fn record(rig: &Rig, kind: JobKind, job: JobId, target: Option<&str>, resumable: bool) {
    let dirs = BackupDirs::new(&rig.cfg.state_dir);
    dirs.ensure_desktop_dir("main").unwrap();
    JobRecord {
        format: FORMAT,
        job_id: job.hex(),
        kind: kind_name(kind).into(),
        desktop_id: "main".into(),
        started_unix: 1_800_000_000,
        helper: job.helper_name().to_string(),
        snapshot: (kind == JobKind::Backup).then(|| "hx-backup-20261127T030000Z-ab12".to_string()),
        target: target.map(str::to_string),
        resumable,
    }
    .store(&dirs.job_path("main").unwrap())
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_cleans_each_leftover_and_keeps_a_resumable_target_only_when_the_record_says_so() {
    let rig = Rig::raw();
    let (t1, t2, t3) = ("hx-restore-aaaa", "hx-restore-bbbb", "hx-restore-cccc");
    rig.host.add_helper(job(1));
    rig.host.add_helper(job(2));
    rig.host
        .add_snapshot("hx-main", "hx-backup-20261127T030000Z-ab12");
    rig.host
        .add_snapshot("hx-main", "hx-backup-20261126T030000Z-cd34");
    rig.host.add_target(t1, Some(job(3)));
    rig.host.add_target(t2, Some(job(4)));
    rig.host.add_unmarked_target(t3);
    leave_socket(&rig.cfg.run_dir, &format!("{}.sock", job(1).hex()));
    leave_socket(&rig.cfg.run_dir, "other.sock");
    std::fs::write(rig.cfg.run_dir.join("keep.txt"), b"not a socket").unwrap();
    record(&rig, JobKind::Restore, job(3), Some(t1), true);

    let rep = rig.runner.recover().await;
    assert!(rep.complete, "{rep:?}");
    assert!(rig.runner.is_recovered());
    // 1. every helper
    assert!(rig.host.helpers().is_empty());
    assert_eq!(rep.helpers_deleted.len(), 2);
    // 2. every socket, and only sockets
    let left: Vec<_> = std::fs::read_dir(&rig.cfg.run_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, vec!["keep.txt".to_string()]);
    // 3. every backup snapshot
    assert!(rig.host.snapshots("hx-main").is_empty());
    // 4. the target whose record says it can resume stays; the other goes; an unmarked one is
    // never touched
    let mut targets = rig.host.targets();
    targets.sort();
    assert_eq!(targets, vec![t1.to_string()]);
    assert_eq!(rig.host.unmarked_targets(), vec![t3.to_string()]);
    assert!(
        !rig.host.log().iter().any(|l| l.contains(t3)),
        "an instance without the marker is never touched"
    );
    // 5. the Drive helper is stopped
    assert_eq!(rig.host.drive_stops(), 1);
    // 6. the job record is cleared, the kept target moves to resume.json
    assert!(!rig.desktop_dir().join("job.json").exists());
    let resume = rig.runner.resume_point("main").unwrap().unwrap();
    assert_eq!((resume.target.as_str(), resume.job_id), (t1, job(3).hex()));
    assert!(rig.audit().contains("backup recovery"));
    // Repeating it changes nothing, and the target stays because resume.json says so.
    let again = rig.runner.recover().await;
    assert!(again.complete);
    assert_eq!(rig.host.targets(), vec![t1.to_string()]);
    assert!(rig.runner.resume_point("main").unwrap().is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_target_whose_record_does_not_say_resumable_is_deleted_by_recovery() {
    let rig = Rig::raw();
    rig.host.add_target("hx-restore-aaaa", Some(job(3)));
    record(
        &rig,
        JobKind::Restore,
        job(3),
        Some("hx-restore-aaaa"),
        false,
    );
    let rep = rig.runner.recover().await;
    assert!(rep.complete);
    assert!(rig.host.targets().is_empty());
    assert!(rig.runner.resume_point("main").unwrap().is_none());
    assert!(!rig.desktop_dir().join("job.json").exists());
    // A resume.json that names no instance is removed too.
    ResumeRecord::new(
        job(5),
        &hx_provision::incus::RestoreTargetName::new("hx-restore-gone").unwrap(),
    )
    .store(
        &BackupDirs::new(&rig.cfg.state_dir)
            .resume_path("main")
            .unwrap(),
    )
    .unwrap();
    rig.runner.recover().await;
    assert!(rig.runner.resume_point("main").unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recovery_that_could_not_look_is_repeated_before_any_job_is_admitted() {
    let rig = Rig::raw();
    rig.host.set_list_fails(true);
    let rep = rig.runner.recover().await;
    assert!(!rep.complete);
    assert!(!rig.runner.is_recovered());
    let e = rig.runner.start(rig.backup_request()).await.err().unwrap();
    assert_eq!(e, StartError::Recovering);
    assert_eq!(rig.host.count("create_snapshot"), 0);
    rig.host.set_list_fails(false);
    assert!(rig.runner.recover().await.complete);
    rig.worker(|w| {
        let s = w.put(hx_ipc::repo::pb::ObjectType::Snapshot, &body(10, 1));
        w.finish_ok(hx_ipc::repo::pb::JobResult {
            snapshot_id: bytes::Bytes::copy_from_slice(&s),
            ..Default::default()
        });
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    assert!(rig.outcome(&h).await.result.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_corrupt_job_record_refuses_that_desktop_and_is_left_alone() {
    let rig = Rig::raw();
    let dirs = BackupDirs::new(&rig.cfg.state_dir);
    dirs.ensure_desktop_dir("main").unwrap();
    let p = dirs.job_path("main").unwrap();
    std::fs::write(&p, "{ this is not a job record").unwrap();
    let rep = rig.runner.recover().await;
    assert!(
        rep.complete,
        "one corrupt record does not stop other desktops: {rep:?}"
    );
    assert!(rep.failures.iter().any(|f| f.contains("corrupt")));
    assert_eq!(
        std::fs::read_to_string(&p).unwrap(),
        "{ this is not a job record"
    );
    let e = rig.runner.start(rig.backup_request()).await.err().unwrap();
    assert!(matches!(e, StartError::Record(_)), "{e:?}");
    assert_eq!(
        std::fs::read_to_string(&p).unwrap(),
        "{ this is not a job record"
    );
    assert_eq!(rig.host.count("create_snapshot"), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn teardown_cancels_the_active_job_and_removes_every_target_resumable_or_not() {
    let rig = Rig::ready().await;
    rig.worker(|w| w.until_closed()); // ignores Cancel: the force-stop after 30 s ends it
    let mut req = rig.request(JobSpec::Restore {
        snapshot_id: [1; 32],
        verify_existing: false,
        resumable: true,
    });
    req.folder = None;
    let h = rig.runner.start(req).await.unwrap();
    rig.until("the job to run", || h.status().state == JobState::Running)
        .await;
    // Another leftover, and a socket.
    rig.host.add_target("hx-restore-other", None);
    rig.host.add_helper(job(9));
    leave_socket(&rig.cfg.run_dir, "x.sock");
    let runner = rig.runner.clone();
    let td = tokio::spawn(async move { runner.teardown_cleanup(&["main".to_string()]).await });
    rig.until("the cancel", || h.status().state == JobState::Cancelling)
        .await;
    rig.advance(31_000, 31_000).await;
    let rep = tokio::time::timeout(std::time::Duration::from_secs(30), td)
        .await
        .expect("teardown finished")
        .unwrap();
    assert!(rep.complete, "{rep:?}");
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::Cancelled);
    // The job kept its resumable target, and the teardown deleted it with the rest.
    assert!(rig.host.targets().is_empty(), "{:?}", rig.host.targets());
    assert!(rig.host.helpers().is_empty());
    assert_eq!(std::fs::read_dir(&rig.cfg.run_dir).unwrap().count(), 0);
    assert!(rig.runner.resume_point("main").unwrap().is_none());
    assert!(!rig.desktop_dir().join("job.json").exists());
    let log = rig.host.log();
    let cancel_end = log
        .iter()
        .position(|l| l.starts_with("force_delete_helper"))
        .unwrap();
    let del = log
        .iter()
        .rposition(|l| l.starts_with("delete_restore_target"))
        .unwrap();
    assert!(
        cancel_end < del,
        "the job is finished before the teardown deletes: {log:?}"
    );
}

// ----- through the daemon ---------------------------------------------------------------------

fn seed_leftovers(h: &Harness) {
    let mark = |kind: &str, j: JobId| -> FakeInstance {
        FakeInstance {
            status: "Stopped".into(),
            config: [
                ("user.hx.kind".to_string(), kind.to_string()),
                ("user.hx.job".to_string(), j.hex()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        }
    };
    h.incus
        .add_desktop("hx-main", "ubuntu-24.04-xfce-basic", "alice", false);
    h.daemon.register_desktop("main").unwrap();
    h.incus.with(|s| {
        s.instances.insert(
            job(1).helper_name().to_string(),
            mark("backup-worker", job(1)),
        );
        s.instances.insert(
            format!("hx-restore-{}", job(2).hex()),
            mark("restore-target", job(2)),
        );
        // Ours by name, not by marker: never touched.
        s.instances
            .insert("hx-restore-plain".into(), FakeInstance::default());
        s.instances
            .get_mut("hx-main")
            .unwrap()
            .snapshots
            .push("hx-backup-20261127T030000Z-ab12".into());
    });
    let run = &h.daemon.cfg.backup_run_dir;
    std::fs::create_dir_all(run).unwrap();
    leave_socket(run, &format!("{}.sock", job(1).hex()));
}

fn names(h: &Harness) -> Vec<String> {
    h.incus.instance_names()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn privd_start_runs_crash_recovery_before_any_backup_job() {
    let h = Harness::start(GW);
    seed_leftovers(&h);
    assert!(!h.daemon.backups().is_recovered());
    h.daemon.recover_backups().await;
    assert!(h.daemon.backups().is_recovered());
    let n = names(&h);
    assert!(!n.contains(&job(1).helper_name().to_string()), "{n:?}");
    assert!(
        !n.contains(&format!("hx-restore-{}", job(2).hex())),
        "{n:?}"
    );
    assert!(
        n.contains(&"hx-restore-plain".to_string()),
        "an unmarked instance is never touched"
    );
    assert!(n.contains(&"hx-main".to_string()));
    assert!(
        h.incus
            .with(|s| s.instances["hx-main"].snapshots.is_empty())
    );
    assert_eq!(
        std::fs::read_dir(&h.daemon.cfg.backup_run_dir)
            .unwrap()
            .count(),
        0
    );
    let calls = h.runner.calls();
    assert!(
        calls
            .iter()
            .any(|p| p.tool == Tool::Systemctl && p.args == ["stop", "hx-drive.service"]),
        "{calls:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn destroy_desktop_cleans_helpers_targets_and_sockets_before_it_tears_down() {
    let h = Harness::start(GW);
    seed_leftovers(&h);
    let r = h
        .daemon
        .handle(
            request(
                1,
                Command::DestroyDesktop(pb::DestroyDesktopRequest {
                    desktop_id: "main".into(),
                    confirm_destroy: true,
                }),
            ),
            Ctx::new(Role::Admin),
        )
        .await;
    assert!(matches!(r.result, Some(R::DestroyDesktop(_))), "{r:?}");
    let n = names(&h);
    assert!(!n.contains(&"hx-main".to_string()));
    assert!(!n.contains(&job(1).helper_name().to_string()), "{n:?}");
    assert!(
        !n.contains(&format!("hx-restore-{}", job(2).hex())),
        "{n:?}"
    );
    assert!(n.contains(&"hx-restore-plain".to_string()));
    assert_eq!(
        std::fs::read_dir(&h.daemon.cfg.backup_run_dir)
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uninstall_cleans_helpers_targets_and_sockets_in_both_modes() {
    for keep in [true, false] {
        let h = Harness::start(GW);
        seed_leftovers(&h);
        let r = h
            .daemon
            .handle(
                request(
                    1,
                    Command::Uninstall(pb::UninstallRequest {
                        keep_desktop: keep,
                        confirm_destroy: !keep,
                    }),
                ),
                Ctx::new(Role::Admin),
            )
            .await;
        assert!(
            matches!(r.result, Some(R::Uninstall(_))),
            "keep={keep}: {r:?}"
        );
        let n = names(&h);
        assert!(
            !n.contains(&job(1).helper_name().to_string()),
            "keep={keep}: {n:?}"
        );
        assert!(
            !n.contains(&format!("hx-restore-{}", job(2).hex())),
            "keep={keep}: {n:?}"
        );
        assert!(n.contains(&"hx-restore-plain".to_string()));
        assert_eq!(n.contains(&"hx-main".to_string()), keep, "keep={keep}");
        assert_eq!(
            std::fs::read_dir(&h.daemon.cfg.backup_run_dir)
                .unwrap()
                .count(),
            0
        );
    }
    let _ = Arc::new(());
}
