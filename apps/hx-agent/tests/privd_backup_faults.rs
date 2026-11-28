//! The failure paths of the job runner: cancel, deadlines, silence, the end of the Drive link,
//! the guard timer, the section 30 policy, the hash check, the Drive's classes and their effects
//! (ipc.md sections 25 to 33). Time is a manual monotonic clock: a 12 h deadline is one call.

mod backup_common;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use backup_common::*;
use bytes::Bytes;
use hx_agent::privd::backup::completed::{CompletedBackup, CompletedRecord, Retention};
use hx_agent::privd::backup::runner::{JobHandle, StartError};
use hx_agent::privd::backup::spec::JobSpec;
use hx_agent::privd::backup::{AlertKind, Failure, JobState, LinkName};
use hx_agent::privd::state::Flag;
use hx_ipc::repo::pb::{self, ErrorClass, ObjectType as T, WorkerError};

fn idle(w: &mut WorkerPeer) {
    w.until_closed();
}

async fn running(rig: &Rig, h: &JobHandle) {
    rig.until("the job to run", || h.status().state == JobState::Running)
        .await;
}

fn snapshot_result(w: &mut WorkerPeer) {
    let s = w.put(T::Snapshot, &body(10, 1));
    w.finish_ok(pb::JobResult {
        snapshot_id: Bytes::copy_from_slice(&s),
        ..Default::default()
    });
}

// ----- cancel -------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_within_30_seconds_ends_in_order_without_a_force_stop() {
    let rig = Rig::ready().await;
    rig.worker(|w| {
        w.wait_cancel();
        w.finish_err(WorkerError::Cancelled);
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    running(&rig, &h).await;
    h.cancel();
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::Cancelled);
    let log = rig.host.log();
    assert!(
        !log.iter().any(|l| l.starts_with("force_delete")),
        "{log:?}"
    );
    assert!(log.iter().any(|l| l.starts_with("finish_helper")));
    // Everything is cleaned up: the snapshot, the helper, the record.
    assert!(rig.host.snapshots("hx-main").is_empty());
    assert!(!rig.desktop_dir().join("job.json").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_after_30_seconds_force_stops_the_helper() {
    let rig = Rig::ready().await;
    rig.worker(idle); // ignores Cancel
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    running(&rig, &h).await;
    h.cancel();
    rig.until("the cancel", || h.status().state == JobState::Cancelling)
        .await;
    // Inside the grace nothing is forced.
    rig.advance(20_000, 10_000).await;
    assert_ne!(h.status().state, JobState::Finished);
    assert_eq!(rig.host.count("force_delete"), 0);
    // 30 s after the cancel: the helper is force-stopped, verified gone, the Drive session closed.
    rig.advance(31_000, 31_000).await;
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::Cancelled);
    assert_eq!(
        rig.host.count("force_delete_helper"),
        1,
        "{:?}",
        rig.host.log()
    );
    assert!(rig.host.helpers().is_empty());
    assert!(rig.host.snapshots("hx-main").is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_upload_is_aborted_and_closed_with_an_empty_end() {
    let rig = Rig::ready().await;
    rig.worker(|w| {
        let req = w.request(pb::repo_request::Op::Write(pb::Write {
            object_type: T::Pack as i32,
            id: Bytes::copy_from_slice(&[7u8; 32]),
            size: 3 * 1024 * 1024,
        }));
        w.send_body(req, &body(3 * 1024 * 1024, 5), 2); // two frames, no END yet
        w.wait_cancel();
        // The Drive helper answered the cancelled request; privd relayed it.
        assert_eq!(w.wait(req), Reply::Error(ErrorClass::Cancelled));
        // The aborted upload is closed with an END, then the job ends.
        w.p.send_data(req, true, &[]).unwrap();
        w.finish_err(WorkerError::Cancelled);
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    rig.until("the upload to start", || {
        rig.drive
            .seen()
            .iter()
            .filter(|s| matches!(s, Seen::Data { .. }))
            .count()
            >= 2
    })
    .await;
    h.cancel();
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::Cancelled);
    let seen = rig.drive.seen();
    assert!(
        seen.iter().any(|s| matches!(s, Seen::CancelRequest(_))),
        "{seen:?}"
    );
    // privd closed its side of the upload with an empty END, and never committed the object.
    assert!(
        seen.iter().any(|s| matches!(
            s,
            Seen::Data {
                len: 0,
                end: true,
                ..
            }
        )),
        "{seen:?}"
    );
    assert!(rig.drive.objects(T::Pack).is_empty());
    assert_eq!(rig.host.count("force_delete"), 0);
}

// ----- deadlines ------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_job_kind_has_its_deadline_and_a_deadline_is_a_cancel() {
    let hour = 3600u64;
    let cases: Vec<(&str, JobSpec, bool, u64)> = vec![
        ("INIT", JobSpec::Init, true, 30 * 60),
        (
            "KEYS",
            JobSpec::Keys {
                add: false,
                remove_key_ids: vec![],
            },
            false,
            10 * 60,
        ),
        ("SNAPSHOTS", JobSpec::Snapshots, false, 10 * 60),
        (
            "RESTORE_PLAN",
            JobSpec::RestorePlan {
                snapshot_id: [1; 32],
            },
            false,
            10 * 60,
        ),
        (
            "CHECK",
            JobSpec::Check {
                read_data_percent: 0,
            },
            false,
            6 * hour,
        ),
        (
            "FORGET_PRUNE",
            JobSpec::ForgetPrune {
                retention: Retention::EVERY_24H,
            },
            false,
            6 * hour,
        ),
        (
            "RESTORE",
            JobSpec::Restore {
                snapshot_id: [1; 32],
                verify_existing: false,
                resumable: false,
            },
            false,
            12 * hour,
        ),
        (
            "BACKUP",
            JobSpec::Backup(Default::default()),
            false,
            30 * hour,
        ),
    ];
    for (name, spec, needs_key, secs) in cases {
        let rig = Rig::ready().await;
        rig.worker(idle);
        let mut req = rig.request(spec);
        if needs_key {
            req.new_key_password = Some(zeroizing(b"recovery-key-0123456789"));
        }
        let h = rig.runner.start(req).await.unwrap();
        running(&rig, &h).await;
        // One second before the deadline: still running, nothing asked of the worker.
        rig.advance((secs - 1) * 1000, (secs - 1) * 1000).await;
        assert_eq!(
            h.status().state,
            JobState::Running,
            "{name} 1 s before its deadline"
        );
        // At the deadline the worker is asked to stop...
        rig.advance(2_000, 2_000).await;
        rig.until("the deadline", || h.status().state == JobState::Cancelling)
            .await;
        // ...and 30 s later, having ignored it, it is force-stopped.
        rig.advance(31_000, 31_000).await;
        let out = rig.outcome(&h).await;
        assert_eq!(
            out.result.as_ref().unwrap_err(),
            &Failure::Deadline,
            "{name}"
        );
        assert_eq!(
            rig.host.count("force_delete_helper"),
            1,
            "{name}: {:?}",
            rig.host.log()
        );
        assert!(rig.host.helpers().is_empty(), "{name}");
    }
}

// ----- silence --------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forty_five_seconds_of_silence_from_the_worker_kills_the_job() {
    let rig = Rig::ready().await;
    rig.worker(|w| {
        w.p.mute.store(true, Ordering::SeqCst); // reads, never answers a Ping
        w.until_closed();
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    running(&rig, &h).await;
    rig.advance(40_000, 10_000).await;
    assert_ne!(
        h.status().state,
        JobState::Finished,
        "44 s is not silence yet"
    );
    rig.advance(20_000, 10_000).await;
    let out = rig.outcome(&h).await;
    assert_eq!(
        out.result.as_ref().unwrap_err(),
        &Failure::Silent(LinkName::Worker)
    );
    assert_eq!(rig.host.count("force_delete_helper"), 1);
    assert!(rig.audit().contains("SILENT"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forty_five_seconds_of_silence_from_the_drive_helper_kills_the_job() {
    let rig = Rig::ready().await;
    rig.drive.mute.store(true, Ordering::SeqCst);
    rig.worker(idle);
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    running(&rig, &h).await;
    rig.advance(60_000, 10_000).await;
    let out = rig.outcome(&h).await;
    assert_eq!(
        out.result.as_ref().unwrap_err(),
        &Failure::Silent(LinkName::Drive)
    );
    assert_eq!(rig.host.count("force_delete_helper"), 1);
}

// ----- the end of the Drive link ----------------------------------------------------------------

fn list_worker(w: &mut WorkerPeer) {
    // A request that the held Drive helper never answers; the answer, if any, is UNAVAILABLE.
    let req = w.request(pb::repo_request::Op::List(pb::List {
        object_type: T::Pack as i32,
    }));
    if let Some(Reply::Error(ErrorClass::Unavailable)) = w.try_wait(req) {
        w.wait_cancel();
        w.finish_err(WorkerError::Cancelled);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drive_end_of_stream_at_a_frame_boundary_is_unavailable_and_not_a_violation() {
    let rig = Rig::ready().await;
    rig.drive.knobs.lock().unwrap().hold_lists = true;
    rig.worker(list_worker);
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    rig.until("the list request", || {
        rig.drive
            .seen()
            .iter()
            .any(|s| matches!(s, Seen::Request(r) if r.starts_with("list")))
    })
    .await;
    rig.drive.cmd.send(DriveCmd::Close).unwrap();
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::Unavailable);
    let audit = rig.audit();
    assert!(
        !audit.contains("DRIVE_PROTOCOL"),
        "a clean end is not a violation:\n{audit}"
    );
    assert!(!audit.to_lowercase().contains("violation"), "{audit}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cut_drive_frame_is_a_violation_and_is_audited() {
    let rig = Rig::ready().await;
    rig.drive.knobs.lock().unwrap().hold_lists = true;
    rig.worker(list_worker);
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    rig.until("the list request", || {
        rig.drive
            .seen()
            .iter()
            .any(|s| matches!(s, Seen::Request(r) if r.starts_with("list")))
    })
    .await;
    rig.drive.cmd.send(DriveCmd::CutClose).unwrap();
    let out = rig.outcome(&h).await;
    assert!(
        matches!(out.result.as_ref().unwrap_err(), Failure::DriveProtocol(_)),
        "{:?}",
        out.result
    );
    assert!(rig.audit().contains("DRIVE_PROTOCOL"));
    assert_eq!(
        rig.host.count("force_delete_helper"),
        1,
        "a violation has no grace"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failure_after_read_begin_reaches_privd_as_its_class_and_has_its_effect() {
    for (class, flag, backoff) in [
        (ErrorClass::AuthRevoked, true, false),
        (ErrorClass::DailyLimit, false, true),
        (ErrorClass::Transient, false, false),
    ] {
        let rig = Rig::ready().await;
        let pack = [9u8; 32];
        rig.drive.put(T::Pack, &pack, &body(2_000_000, 4));
        rig.drive.knobs.lock().unwrap().fail_reads = Some((0, class));
        rig.worker(move |w| {
            let req = w.request(pb::repo_request::Op::ReadFull(pb::ReadFull {
                object_type: T::Pack as i32,
                id: Bytes::copy_from_slice(&pack),
            }));
            // The download began and cannot be answered; the job is asked to stop.
            w.wait_cancel();
            let _ = req;
            w.finish_err(WorkerError::Cancelled);
        });
        let h = rig.runner.start(rig.backup_request()).await.unwrap();
        let out = rig.outcome(&h).await;
        assert_eq!(
            out.result.as_ref().unwrap_err(),
            &Failure::Repo(class),
            "{class:?}"
        );
        assert_eq!(
            rig.env.has_flag(None, Flag::DriveReconnect),
            flag,
            "{class:?}"
        );
        let p = rig.desktop_dir().join("backoff.json");
        assert_eq!(p.exists(), backoff, "{class:?}");
        assert!(!rig.audit().contains("DRIVE_PROTOCOL"));
    }
}

// ----- the guard timer --------------------------------------------------------------------------

fn held_list_job(rig: &Rig) {
    rig.drive.knobs.lock().unwrap().hold_lists = true;
    rig.worker(|w| {
        let r = w.list(T::Pack);
        assert_eq!(r, Reply::List(vec![]));
        snapshot_result(w);
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_guard_restarts_on_every_sign_of_life_and_is_never_a_fixed_total() {
    let rig = Rig::ready().await;
    held_list_job(&rig);
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    rig.until("the list request", || {
        rig.drive
            .seen()
            .iter()
            .any(|s| matches!(s, Seen::Request(r) if r.starts_with("list")))
    })
    .await;
    // 20 minutes with no sign of life: still inside the guard (31 minutes).
    rig.advance(20 * 60_000, 20 * 60_000).await;
    assert_ne!(h.status().state, JobState::Finished);
    // A sign of life (the helper is retrying) restarts the timer...
    rig.drive
        .cmd
        .send(DriveCmd::Event(pb::Event {
            kind: pb::EventKind::Retrying as i32,
            until_ms: 0,
            error_class: 0,
        }))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    // ...so 20 more minutes, 40 in all since the request, are fine too.
    rig.advance(20 * 60_000, 20 * 60_000).await;
    assert_ne!(
        h.status().state,
        JobState::Finished,
        "there is no fixed total"
    );
    // The answer comes after 40 minutes, and the job completes.
    rig.drive.knobs.lock().unwrap().hold_lists = false;
    let out = rig.outcome(&h).await;
    assert!(out.result.is_ok(), "{:?}\n{}", out.result, rig.audit());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_without_any_sign_of_life_for_the_guard_ends_the_drive_session() {
    let rig = Rig::ready().await;
    held_list_job(&rig);
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    rig.until("the list request", || {
        rig.drive
            .seen()
            .iter()
            .any(|s| matches!(s, Seen::Request(r) if r.starts_with("list")))
    })
    .await;
    rig.advance(30 * 60_000, 30 * 60_000).await;
    assert_ne!(
        h.status().state,
        JobState::Finished,
        "30 minutes is inside the guard"
    );
    rig.advance(2 * 60_000, 2 * 60_000).await;
    rig.advance(31_000, 31_000).await;
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::Guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daily_limit_pause_suspends_the_guard() {
    let rig = Rig::ready().await;
    held_list_job(&rig);
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    rig.until("the list request", || {
        rig.drive
            .seen()
            .iter()
            .any(|s| matches!(s, Seen::Request(r) if r.starts_with("list")))
    })
    .await;
    // The gate pauses for 2 hours.
    let until_ms = (rig.env.now.load(Ordering::SeqCst) + 2 * 3600) * 1000;
    rig.drive
        .cmd
        .send(DriveCmd::Event(pb::Event {
            kind: pb::EventKind::PausedDailyLimit as i32,
            until_ms,
            error_class: 0,
        }))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(h.status().paused_until_ms, Some(until_ms));
    // 100 minutes without a word: more than the guard, inside the pause plus the guard.
    rig.advance(100 * 60_000, 20 * 60_000).await;
    assert_ne!(h.status().state, JobState::Finished);
    rig.drive.knobs.lock().unwrap().hold_lists = false;
    let out = rig.outcome(&h).await;
    assert!(out.result.is_ok(), "{:?}", out.result);
}

// ----- policy and hash ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_the_job_may_not_make_is_refused_audited_and_backs_off() {
    let rig = Rig::ready().await;
    rig.drive.put(T::Pack, &[5u8; 32], b"somebody's pack");
    rig.worker(|w| {
        // A BACKUP job may remove an INDEX, never a PACK (the anti-ransomware property).
        let req = w.request(pb::repo_request::Op::Remove(pb::Remove {
            object_type: T::Pack as i32,
            id: Bytes::copy_from_slice(&[5u8; 32]),
        }));
        let _ = w.try_wait(req);
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::PolicyDenied);
    assert_eq!(
        rig.drive.objects(T::Pack).len(),
        1,
        "the pack was not removed"
    );
    assert!(
        !rig.drive
            .seen()
            .iter()
            .any(|s| matches!(s, Seen::Request(r) if r.starts_with("remove"))),
        "a refused request never reaches the Drive helper"
    );
    assert!(rig.audit().contains("POLICY_DENIED"));
    assert_eq!(
        rig.host.count("force_delete_helper"),
        1,
        "the helper is killed"
    );
    // Back-off: no writing job for an hour; a read-only job is still fine.
    let e = rig.runner.start(rig.backup_request()).await.err().unwrap();
    assert!(matches!(e, StartError::Backoff { .. }), "{e:?}");
    rig.worker(|w| {
        w.finish_ok(pb::JobResult {
            snapshots: vec![],
            ..Default::default()
        })
    });
    let h = rig
        .runner
        .start(rig.request(JobSpec::Snapshots))
        .await
        .unwrap();
    assert!(rig.outcome(&h).await.result.is_ok());
    rig.env.now.fetch_add(3601, Ordering::SeqCst);
    rig.worker(snapshot_result);
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    assert!(rig.outcome(&h).await.result.is_ok(), "the back-off ended");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_that_does_not_hash_to_its_id_never_gets_its_end_and_raises_the_alert() {
    let rig = Rig::ready().await;
    let data = body(2_500_000, 3);
    let wrong_id = [0x11u8; 32];
    rig.worker(move |w| {
        let req = w.start_write(T::Pack, &wrong_id, &data);
        let _ = w.try_wait(req);
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::Integrity);
    assert!(rig.drive.objects(T::Pack).is_empty());
    // The Drive helper never got the END that would commit the object. (Whether it got any of
    // the data frames before is not asserted: a failure without grace closes the link and
    // drops what is still queued, so under load none may have been written yet.)
    let seen = rig.drive.seen();
    assert!(
        !seen
            .iter()
            .any(|s| matches!(s, Seen::Data { end: true, .. })),
        "the END of a bad object was forwarded: {seen:?}"
    );
    let alerts = rig.env.alerts.lock().unwrap().clone();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, AlertKind::Integrity);
    assert!(rig.audit().contains("INTEGRITY"));
    assert!(rig.desktop_dir().join("backoff.json").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_workers_own_integrity_refusal_alerts_the_owner_and_backs_off() {
    let rig = Rig::ready().await;
    rig.worker(|w| w.finish_err(WorkerError::Integrity));
    let h = rig
        .runner
        .start(rig.request(JobSpec::ForgetPrune {
            retention: Retention::EVERY_24H,
        }))
        .await
        .unwrap();
    let out = rig.outcome(&h).await;
    assert_eq!(
        out.result.as_ref().unwrap_err(),
        &Failure::WorkerFailed(WorkerError::Integrity)
    );
    assert_eq!(rig.env.alerts.lock().unwrap().len(), 1);
    let e = rig
        .runner
        .start(rig.request(JobSpec::ForgetPrune {
            retention: Retention::EVERY_24H,
        }))
        .await
        .err()
        .unwrap();
    assert!(
        matches!(e, StartError::Backoff { .. }),
        "not retried in a loop: {e:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_breaks_a_rule_of_the_link_is_a_protocol_failure() {
    let rig = Rig::ready().await;
    rig.worker(|w| {
        // A `JobResult` while a request is outstanding, written past the worker's own checks.
        let _req = w.request(pb::repo_request::Op::List(pb::List {
            object_type: T::Pack as i32,
        }));
        let f = pb::RepoFrame {
            frame: Some(pb::repo_frame::Frame::Result(pb::JobResult {
                ok: false,
                error: WorkerError::Engine as i32,
                ..Default::default()
            })),
        };
        let bytes =
            hx_ipc::repo::encode_message(&f, hx_ipc::repo::Endpoint::PrivdWorkerLink).unwrap();
        w.p.send_raw(&bytes);
        w.until_closed();
    });
    rig.drive.knobs.lock().unwrap().hold_lists = true;
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    let out = rig.outcome(&h).await;
    assert!(
        matches!(out.result.as_ref().unwrap_err(), Failure::WorkerProtocol(_)),
        "{:?}",
        out.result
    );
    assert!(rig.audit().contains("WORKER_PROTOCOL"));
    assert_eq!(rig.host.count("force_delete_helper"), 1);
}

// ----- INIT and CONFIG --------------------------------------------------------------------------

fn init_request(rig: &Rig) -> hx_agent::privd::backup::runner::JobRequest {
    let mut r = rig.request(JobSpec::Init);
    r.new_key_password = Some(zeroizing(b"recovery-key-0123456789"));
    r
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_config_write_answered_permission_is_audited() {
    let rig = Rig::ready().await;
    rig.drive.knobs.lock().unwrap().write_error = Some((T::Config, ErrorClass::Permission));
    rig.worker(|w| {
        assert_eq!(w.list(T::Config), Reply::List(vec![]));
        assert_eq!(
            w.call(pb::repo_request::Op::Create(pb::Create {})),
            Reply::Done
        );
        let r = w.write(T::Config, &[0u8; 32], b"the repository config");
        assert_eq!(r, Reply::Error(ErrorClass::Permission));
        w.finish_err(WorkerError::Engine);
    });
    let h = rig.runner.start(init_request(&rig)).await.unwrap();
    let out = rig.outcome(&h).await;
    assert_eq!(
        out.result.as_ref().unwrap_err(),
        &Failure::Repo(ErrorClass::Permission)
    );
    let audit = rig.audit();
    assert!(
        audit.contains("PERMISSION") && audit.contains("write CONFIG"),
        "{audit}"
    );
    // The Drive helper was asked to create the folder.
    assert!(rig.drive.opens.lock().unwrap()[0].create);
    // PERMISSION has no effect on privd's state beyond the audit line.
    assert!(!rig.env.has_flag(None, Flag::DriveReconnect));
    assert!(!rig.desktop_dir().join("backoff.json").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_init_config_write_is_allowed_only_after_privd_saw_no_config() {
    // Without a listing, and over an existing config: refused. After an empty listing: allowed.
    for (list_first, existing, ok) in [
        (false, false, false),
        (true, true, false),
        (true, false, true),
    ] {
        let rig = Rig::ready().await;
        if existing {
            rig.drive.put(T::Config, &[0u8; 32], b"old config");
        }
        rig.worker(move |w| {
            if list_first {
                let _ = w.list(T::Config);
            }
            let req = w.start_write(T::Config, &[0u8; 32], b"new config");
            if let Some(Reply::Done) = w.try_wait(req) {
                w.put(T::Key, b"a key file");
                w.finish_ok(pb::JobResult {
                    key_ids: vec![Bytes::from(vec![1u8; 32]), Bytes::from(vec![2u8; 32])],
                    ..Default::default()
                });
            }
        });
        let h = rig.runner.start(init_request(&rig)).await.unwrap();
        let out = rig.outcome(&h).await;
        assert_eq!(
            out.result.is_ok(),
            ok,
            "{list_first} {existing}: {:?}",
            out.result
        );
        if !ok {
            assert_eq!(out.result.as_ref().unwrap_err(), &Failure::PolicyDenied);
        }
    }
}

// ----- the Drive session --------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_open_repo_costs_no_snapshot_and_has_its_effect() {
    for (class, expect_flag, expect_taken, expect_backoff) in [
        (ErrorClass::AuthRevoked, true, false, false),
        (ErrorClass::LeaseHeld, false, true, false),
        (ErrorClass::DailyLimit, false, false, true),
    ] {
        let rig = Rig::ready().await;
        rig.drive.knobs.lock().unwrap().open_error = Some(class);
        let h = rig.runner.start(rig.backup_request()).await.unwrap();
        let out = rig.outcome(&h).await;
        assert_eq!(out.result.as_ref().unwrap_err(), &Failure::Repo(class));
        assert_eq!(
            rig.host.count("create_snapshot"),
            0,
            "the Drive session opens first"
        );
        assert_eq!(rig.host.count("create_helper"), 0);
        assert_eq!(
            rig.env.has_flag(None, Flag::DriveReconnect),
            expect_flag,
            "{class:?}"
        );
        assert_eq!(
            rig.env.has_flag(Some("main"), Flag::BackupTakenOver),
            expect_taken
        );
        assert_eq!(
            rig.desktop_dir().join("backoff.json").exists(),
            expect_backoff
        );
        assert!(!rig.desktop_dir().join("job.json").exists());
        if expect_taken {
            let e = rig.runner.start(rig.backup_request()).await.err().unwrap();
            assert_eq!(e, StartError::TakenOver);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_takeover_starts_no_write_job_for_two_minutes() {
    let rig = Rig::ready().await;
    rig.worker(|w| w.finish_ok(pb::JobResult::default()));
    let mut req = rig.request(JobSpec::Snapshots);
    req.takeover = true;
    let h = rig.runner.start(req).await.unwrap();
    assert!(rig.outcome(&h).await.result.is_ok());
    assert!(rig.drive.opens.lock().unwrap()[0].takeover);
    let e = rig.runner.start(rig.backup_request()).await.err().unwrap();
    assert!(matches!(e, StartError::Backoff { .. }));
    rig.env.now.fetch_add(121, Ordering::SeqCst);
    rig.worker(snapshot_result);
    assert!(rig.runner.start(rig.backup_request()).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_snapshot_or_helper_leaves_nothing_and_a_failed_cleanup_is_finished_later() {
    // The helper cannot be created: the snapshot that was taken is deleted, the record is gone.
    let rig = Rig::ready().await;
    rig.host.fail_once(
        "create_helper",
        hx_agent::privd::backup::host::HostError::Failed("boom".into()),
    );
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    let out = rig.outcome(&h).await;
    assert!(matches!(
        out.result.as_ref().unwrap_err(),
        Failure::HelperFailed(_)
    ));
    assert!(rig.host.snapshots("hx-main").is_empty());
    assert!(!rig.desktop_dir().join("job.json").exists());
    // The snapshot cannot be taken at all.
    rig.host.fail_once(
        "create_snapshot",
        hx_agent::privd::backup::host::HostError::Failed("boom".into()),
    );
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    let out = rig.outcome(&h).await;
    assert!(matches!(
        out.result.as_ref().unwrap_err(),
        Failure::SnapshotFailed(_)
    ));
    assert_eq!(rig.host.count("create_helper"), 1);
    // A snapshot that cannot be deleted keeps the record; the next admission cleans it first.
    rig.host.fail_once(
        "delete_snapshot",
        hx_agent::privd::backup::host::HostError::Failed("busy".into()),
    );
    rig.worker(snapshot_result);
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    assert!(rig.outcome(&h).await.result.is_ok());
    assert!(
        rig.desktop_dir().join("job.json").exists(),
        "the record stays while a leftover does"
    );
    assert_eq!(rig.host.snapshots("hx-main").len(), 1);
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    assert!(rig.outcome(&h).await.result.is_ok());
    assert!(
        rig.host.snapshots("hx-main").is_empty(),
        "the leftover was removed before the new job"
    );
}

// ----- retention reads only from the record -------------------------------------------------------

fn record_entry(n: u8, t: u64) -> CompletedBackup {
    CompletedBackup {
        snapshot_id: hex(&[n; 32]),
        job_id: "0".repeat(32),
        time_unix: t,
        files_new: 0,
        files_changed: 0,
        files_unmodified: 0,
        bytes_processed: 0,
        bytes_added: 0,
        warnings: 0,
    }
}

fn seed_record(rig: &Rig, entries: &[(u8, u64)]) {
    std::fs::create_dir_all(rig.desktop_dir()).unwrap();
    let mut rec = CompletedRecord::default();
    for (n, t) in entries {
        rec.add(record_entry(*n, *t));
    }
    rec.store(&rig.desktop_dir().join("completed.json"))
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forget_prune_names_only_backups_privd_recorded_and_the_record_follows() {
    let rig = Rig::ready().await;
    seed_record(&rig, &[(1, 100), (2, 200), (3, 300), (4, 400), (5, 500)]);
    // The repository also holds snapshots privd never recorded (forged, dated in the future).
    for n in [1u8, 2, 3, 4, 5, 0xee, 0xef] {
        rig.drive.put(T::Snapshot, &[n; 32], b"snap");
    }
    let tight = Retention {
        last: 0,
        daily: 0,
        weekly: 0,
        monthly: 0,
    };
    let named: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let n2 = named.clone();
    rig.worker(move |w| {
        let Some(pb::job::Spec::ForgetPrune(fp)) = &w.job.spec else {
            panic!("no spec")
        };
        assert!(fp.instant);
        *n2.lock().unwrap() = fp.forget.iter().map(|b| b.to_vec()).collect();
        // The listing the worker sees includes the forged snapshots; privd did not use it.
        let Reply::List(all) = w.list(T::Snapshot) else {
            panic!()
        };
        assert_eq!(all.len(), 7);
        for id in n2.lock().unwrap().clone() {
            let id: [u8; 32] = id.as_slice().try_into().unwrap();
            assert_eq!(w.remove(T::Snapshot, &id), Reply::Done);
        }
        w.finish_ok(pb::JobResult::default());
    });
    let h = rig
        .runner
        .start(rig.request(JobSpec::ForgetPrune { retention: tight }))
        .await
        .unwrap();
    let out = rig.outcome(&h).await;
    assert!(out.result.is_ok(), "{:?}", out.result);
    assert_eq!(
        named.lock().unwrap().clone(),
        vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]],
        "only recorded ids, oldest first, and the floor of two kept"
    );
    // The forged snapshots are still there and still unknown to privd.
    let left = rig.drive.objects(T::Snapshot);
    assert!(left.contains(&vec![0xee; 32]) && left.contains(&vec![0xef; 32]));
    let rec = rig.runner.completed("main").unwrap();
    let ids: Vec<_> = rec.backups.iter().map(|b| b.snapshot_id.clone()).collect();
    assert_eq!(ids, vec![hex(&[4; 32]), hex(&[5; 32])]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_snapshot_privd_did_not_record_cannot_be_removed_by_a_prune() {
    let rig = Rig::ready().await;
    seed_record(&rig, &[(1, 100), (2, 200), (3, 300)]);
    rig.drive.put(T::Snapshot, &[0xee; 32], b"forged");
    rig.worker(|w| {
        let req = w.request(pb::repo_request::Op::Remove(pb::Remove {
            object_type: T::Snapshot as i32,
            id: Bytes::copy_from_slice(&[0xee; 32]),
        }));
        let _ = w.try_wait(req);
    });
    let tight = Retention {
        last: 0,
        daily: 0,
        weekly: 0,
        monthly: 0,
    };
    let h = rig
        .runner
        .start(rig.request(JobSpec::ForgetPrune { retention: tight }))
        .await
        .unwrap();
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::PolicyDenied);
    assert_eq!(rig.drive.objects(T::Snapshot), vec![vec![0xee; 32]]);
    // The record is untouched by a failed job.
    assert_eq!(rig.runner.completed("main").unwrap().backups.len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_open_repo_that_is_never_answered_is_stale_after_the_guard() {
    let rig = Rig::ready().await;
    rig.drive.knobs.lock().unwrap().hold_open = true;
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    rig.until("OpenRepo", || {
        rig.drive.seen().iter().any(|s| matches!(s, Seen::Open(_)))
    })
    .await;
    rig.advance(32 * 60_000, 32 * 60_000).await;
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::Guard);
    assert_eq!(rig.host.count("create_snapshot"), 0);
}
