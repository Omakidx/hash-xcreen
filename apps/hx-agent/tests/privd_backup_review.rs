//! Regression tests of the review of the job runner: bounded queues, the relay budget, recovery
//! that never drops what it could not look at, create-only snapshots, per-desktop teardown,
//! resumable restores, and the smaller fixes of that round. Each test fails without its fix.

mod backup_common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use backup_common::*;
use bytes::Bytes;
use hx_agent::privd::backup::completed::{CompletedBackup, CompletedRecord, Retention};
use hx_agent::privd::backup::host::HostError;
use hx_agent::privd::backup::runner::StartError;
use hx_agent::privd::backup::slot::{BackupDirs, FORMAT, JobRecord, ResumeRecord, kind_name};
use hx_agent::privd::backup::spec::{BackupParams, JobSpec};
use hx_agent::privd::backup::{Failure, JobState, LinkName};
use hx_agent::privd::progress::ProgressSender;
use hx_agent::privd::state::Flag;
use hx_ipc::repo::pb::{self, ErrorClass, JobKind, ObjectType as T, WorkerError};
use hx_ipc::repo::{Endpoint, encode_message};
use hx_provision::incus::{JobId, RestoreTargetName};

const FLOOD: usize = 1_000_000;

fn job(n: u8) -> JobId {
    JobId::from_bytes([n; 16]).unwrap()
}

fn snapshot_result(w: &mut WorkerPeer) {
    let s = w.put(T::Snapshot, &body(10, 1));
    w.finish_ok(pb::JobResult {
        snapshot_id: Bytes::copy_from_slice(&s),
        ..Default::default()
    });
}

async fn running(rig: &Rig, h: &hx_agent::privd::backup::runner::JobHandle) {
    rig.until("the job to run", || h.status().state == JobState::Running)
        .await;
}

fn frame_bytes(f: pb::repo_frame::Frame, to: Endpoint) -> Vec<u8> {
    encode_message(&pb::RepoFrame { frame: Some(f) }, to).unwrap()
}

fn write_job_record(
    rig: &Rig,
    desktop: &str,
    kind: JobKind,
    j: JobId,
    target: Option<&str>,
    resumable: bool,
    snapshot: Option<&str>,
) {
    let dirs = BackupDirs::new(&rig.cfg.state_dir);
    dirs.ensure_desktop_dir(desktop).unwrap();
    JobRecord {
        format: FORMAT,
        job_id: j.hex(),
        kind: kind_name(kind).into(),
        desktop_id: desktop.into(),
        started_unix: 1_800_000_000,
        helper: j.helper_name().to_string(),
        snapshot: snapshot.map(str::to_string),
        snapshot_id: (kind == JobKind::Restore).then(|| hex(&[1u8; 32])),
        target: target.map(str::to_string),
        target_job: target.map(|_| j.hex()),
        resumable,
    }
    .store(&dirs.job_path(desktop).unwrap())
    .unwrap();
}

fn write_resume(rig: &Rig, desktop: &str, j: JobId, target: &str) {
    let dirs = BackupDirs::new(&rig.cfg.state_dir);
    dirs.ensure_desktop_dir(desktop).unwrap();
    ResumeRecord::new(
        j,
        &RestoreTargetName::new(target).unwrap(),
        &hex(&[1u8; 32]),
    )
    .store(&dirs.resume_path(desktop).unwrap())
    .unwrap();
}

// ----- S-H1: unbounded queues ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_floods_pings_and_never_reads_fails_the_job_and_costs_no_memory() {
    let rig = Rig::ready().await;
    let flooded = Arc::new(AtomicBool::new(false));
    let f2 = flooded.clone();
    rig.worker(move |w| {
        let one = frame_bytes(
            pb::repo_frame::Frame::Ping(pb::Ping { nonce: 3 }),
            Endpoint::PrivdWorkerLink,
        );
        let mut all = Vec::with_capacity(one.len() * FLOOD);
        for _ in 0..FLOOD {
            all.extend_from_slice(&one);
        }
        w.p.send_raw(&all);
        f2.store(true, Ordering::SeqCst);
        // Never reads what privd sends back.
        std::thread::sleep(Duration::from_secs(25));
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    rig.until("the flood to be written", || flooded.load(Ordering::SeqCst))
        .await;
    rig.advance_until_done(&h, 10_000, 2400).await;
    let out = rig.outcome(&h).await;
    assert_eq!(
        out.result.as_ref().unwrap_err(),
        &Failure::Silent(LinkName::Worker),
        "{}",
        rig.audit()
    );
    assert_eq!(rig.runner.relay_slots_free(), 16);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drive_helper_that_floods_pings_and_never_reads_fails_the_job() {
    let rig = Rig::ready().await;
    rig.worker(|w| w.until_closed());
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    running(&rig, &h).await;
    rig.drive.cmd.send(DriveCmd::FloodPings(FLOOD)).unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    rig.advance_until_done(&h, 10_000, 2400).await;
    let out = rig.outcome(&h).await;
    assert_eq!(
        out.result.as_ref().unwrap_err(),
        &Failure::Silent(LinkName::Drive),
        "{}",
        rig.audit()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_sends_requests_and_does_not_read_the_answers_fails_not_the_drive_link() {
    for partial in [false, true] {
        let rig = Rig::ready().await;
        rig.drive.put(T::Pack, &[9u8; 32], &body(4000, 1));
        rig.worker(move |w| {
            // Written past the worker's own checks (it would refuse a ninth request).
            let mut all = Vec::new();
            for i in 1..=200u64 {
                let op = if partial {
                    pb::repo_request::Op::ReadPartial(pb::ReadPartial {
                        object_type: T::Pack as i32,
                        id: Bytes::copy_from_slice(&[9u8; 32]),
                        offset: 0,
                        length: 1,
                    })
                } else {
                    pb::repo_request::Op::List(pb::List {
                        object_type: T::Config as i32,
                    })
                };
                all.extend(frame_bytes(
                    pb::repo_frame::Frame::Request(pb::RepoRequest {
                        req_id: i,
                        op: Some(op),
                    }),
                    Endpoint::PrivdWorkerLink,
                ));
            }
            w.p.send_raw(&all);
            std::thread::sleep(Duration::from_secs(25));
        });
        let h = rig.runner.start(rig.backup_request()).await.unwrap();
        let out = rig.outcome(&h).await;
        let f = out.result.as_ref().unwrap_err();
        assert!(
            matches!(
                f,
                Failure::WorkerProtocol(_) | Failure::Silent(LinkName::Worker)
            ),
            "partial={partial}: {f:?}"
        );
        assert_ne!(f, &Failure::Silent(LinkName::Drive));
        rig.until("the slots to come back", || {
            rig.runner.relay_slots_free() == 16
        })
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_job_reserves_its_relay_slots_and_a_fifth_job_is_refused() {
    let rig = Rig::ready_with(&["main", "d2", "d3", "d4", "d5"]).await;
    rig.worker(|w| w.until_closed());
    let mut hs = Vec::new();
    for d in ["main", "d2", "d3", "d4"] {
        let mut req = rig.backup_request();
        req.desktop_id = d.into();
        hs.push(rig.runner.start(req).await.unwrap());
    }
    assert_eq!(rig.runner.relay_slots_free(), 0);
    let mut req = rig.backup_request();
    req.desktop_id = "d5".into();
    assert_eq!(rig.runner.start(req).await.err().unwrap(), StartError::Busy);
    // The jobs that run are not starved by the refusal: cancel them all and the slots return.
    for h in &hs {
        h.cancel();
    }
    for h in &hs {
        rig.until("the cancel to be seen", || {
            matches!(
                h.status().state,
                JobState::Cancelling | JobState::CleaningUp | JobState::Finished
            )
        })
        .await;
    }
    rig.advance(31_000, 31_000).await;
    for h in &hs {
        rig.outcome(h).await;
    }
    rig.until("the slots to come back", || {
        rig.runner.relay_slots_free() == 16
    })
    .await;
}

// ----- C-H1: a failed listing destroys the resumable records ---------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_target_listing_leaves_the_resumable_records_alone() {
    let rig = Rig::raw();
    let (t, t0) = ("hx-restore-aaaa", "hx-restore-bbbb");
    rig.host.add_target(t, Some(job(3)));
    rig.host.add_target(t0, Some(job(5)));
    write_job_record(&rig, "main", JobKind::Restore, job(3), Some(t), true, None);
    write_resume(&rig, "main", job(5), t0);
    rig.host.fail_target_listing_once();
    let rep = rig.runner.recover().await;
    assert!(!rep.complete);
    assert!(
        rig.desktop_dir().join("job.json").exists(),
        "the job record survives"
    );
    assert!(
        rig.desktop_dir().join("resume.json").exists(),
        "the resume record survives"
    );
    assert_eq!(rig.host.targets().len(), 2);
    // The repeat looks at everything: the newer target is kept, the older one is deleted, and
    // only one is recorded.
    let rep = rig.runner.recover().await;
    assert!(rep.complete, "{rep:?}");
    assert_eq!(rig.host.targets(), vec![t.to_string()]);
    let r = rig.runner.resume_point("main").unwrap().unwrap();
    assert_eq!(r.target, t);
    assert!(!rig.desktop_dir().join("job.json").exists());
}

// ----- S-M1: a snapshot the worker did not create ----------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_snapshot_the_worker_read_and_wrote_back_is_not_recorded() {
    let rig = Rig::ready().await;
    let x = body(300, 4);
    let xid = sha(&x);
    rig.drive.put(T::Snapshot, &xid, &x);
    let x2 = x.clone();
    rig.worker(move |w| {
        assert_eq!(w.read(T::Snapshot, &xid), Reply::Read(x2.clone()));
        assert_eq!(w.write(T::Snapshot, &xid, &x2), Reply::Done);
        w.finish_ok(pb::JobResult {
            snapshot_id: Bytes::copy_from_slice(&xid),
            ..Default::default()
        });
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    assert!(rig.outcome(&h).await.result.is_ok());
    assert_eq!(rig.runner.completed("main").unwrap().backups.len(), 0);
    assert!(rig.audit().contains("already existed"));
    // An honest backup is still recorded.
    rig.worker(snapshot_result);
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    assert!(rig.outcome(&h).await.result.is_ok());
    assert_eq!(rig.runner.completed("main").unwrap().backups.len(), 1);
}

// ----- C-M1: the next job's entry ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_finishing_job_never_removes_the_entry_of_the_job_that_follows_it() {
    let rig = Rig::ready().await;
    let hold = Arc::new(AtomicBool::new(false));
    let h2 = hold.clone();
    rig.worker(move |w| {
        w.poll_every(Duration::from_millis(5));
        while h2.load(Ordering::SeqCst) {
            let _ = w.pump();
        }
        snapshot_result(w);
    });
    for round in 0..20 {
        hold.store(false, Ordering::SeqCst);
        let a = rig.runner.start(rig.backup_request()).await.unwrap();
        a.finished().await;
        hold.store(true, Ordering::SeqCst);
        let b = loop {
            match rig.runner.start(rig.backup_request()).await {
                Ok(b) => break b,
                Err(StartError::Busy) => tokio::time::sleep(Duration::from_millis(1)).await,
                Err(e) => panic!("{e:?}"),
            }
        };
        // Long enough for a finishing job's late bookkeeping to run, if it were late.
        tokio::time::sleep(Duration::from_millis(60)).await;
        let st = rig.runner.status("main").unwrap();
        assert_eq!(
            st.job_id, b.job_id,
            "round {round}: status names the running job"
        );
        assert!(
            rig.runner.cancel("main"),
            "round {round}: the running job can be cancelled"
        );
        hold.store(false, Ordering::SeqCst);
        rig.outcome(&b).await;
    }
}

// ----- C-M3: teardown is per desktop --------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn destroying_one_desktop_leaves_the_jobs_and_targets_of_another_alone() {
    let rig = Rig::ready_with(&["main", "d2"]).await;
    rig.worker(|w| w.until_closed());
    // d2 has a kept restore target, a leftover helper and records; a third helper has no owner.
    rig.host.add_helper(job(7));
    rig.host.add_target("hx-restore-d2t", Some(job(8)));
    rig.host.add_helper(job(9));
    write_job_record(
        &rig,
        "d2",
        JobKind::Restore,
        job(7),
        Some("hx-restore-d2t"),
        true,
        None,
    );
    write_resume(&rig, "d2", job(8), "hx-restore-d2t");
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    running(&rig, &h).await;
    let main_helper = rig
        .host
        .helpers()
        .into_iter()
        .find(|x| *x != job(7).hex() && *x != job(9).hex())
        .unwrap();
    let runner = rig.runner.clone();
    let td =
        tokio::spawn(async move { runner.teardown_cleanup(&["main".to_string()], false).await });
    rig.until("the cancel", || h.status().state == JobState::Cancelling)
        .await;
    rig.advance(31_000, 31_000).await;
    let rep = tokio::time::timeout(Duration::from_secs(30), td)
        .await
        .unwrap()
        .unwrap();
    assert!(rep.complete, "{rep:?}");
    assert!(rig.outcome(&h).await.result.is_err());
    let helpers = rig.host.helpers();
    assert!(!helpers.contains(&main_helper), "main's helper is gone");
    assert!(
        helpers.contains(&job(7).hex()),
        "d2's helper stays: {helpers:?}"
    );
    assert!(
        helpers.contains(&job(9).hex()),
        "an unattributed helper is left to recovery"
    );
    assert_eq!(rig.host.targets(), vec!["hx-restore-d2t".to_string()]);
    assert!(rig.runner.resume_point("d2").unwrap().is_some());
    assert!(
        BackupDirs::new(&rig.cfg.state_dir)
            .job_path("d2")
            .unwrap()
            .exists()
    );
    // An uninstall is host-wide.
    let rep = rig
        .runner
        .teardown_cleanup(&["main".into(), "d2".into()], true)
        .await;
    assert!(rep.complete);
    assert!(rig.host.helpers().is_empty());
    assert!(rig.host.targets().is_empty());
}

// ----- C-M4: resumable restores ---------------------------------------------------------------------------

fn restore(resumable: bool, verify: bool) -> JobSpec {
    JobSpec::Restore {
        snapshot_id: [1; 32],
        verify_existing: verify,
        resumable,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_target_that_was_never_created_is_not_recorded() {
    let rig = Rig::ready().await;
    rig.host.fail_once(
        "create_helper",
        HostError::Precondition("a check failed".into()),
    );
    let h = rig
        .runner
        .start(rig.request(restore(true, false)))
        .await
        .unwrap();
    let out = rig.outcome(&h).await;
    assert!(matches!(
        out.result.as_ref().unwrap_err(),
        Failure::Precondition(_)
    ));
    assert!(
        rig.runner.resume_point("main").unwrap().is_none(),
        "nothing was created, nothing is kept"
    );
    assert!(rig.host.targets().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kept_target_is_resumed_by_a_resumable_restore_and_never_overwritten_by_another() {
    let rig = Rig::ready().await;
    let t = "hx-restore-aaaa";
    rig.host.add_target(t, Some(job(3)));
    write_resume(&rig, "main", job(3), t);
    // Not resumable: refused, the record is intact.
    let e = rig
        .runner
        .start(rig.request(restore(false, false)))
        .await
        .err()
        .unwrap();
    assert_eq!(e, StartError::ResumePending);
    assert_eq!(rig.runner.resume_point("main").unwrap().unwrap().target, t);
    // Resumable: the helper is built on the kept target, nothing new is created, and the worker
    // is told to verify what is there.
    let verify = Arc::new(Mutex::new(None));
    let v2 = verify.clone();
    rig.worker(move |w| {
        let Some(pb::job::Spec::Restore(r)) = &w.job.spec else {
            panic!("not a restore")
        };
        *v2.lock().unwrap() = Some(r.verify_existing);
        w.finish_ok(pb::JobResult::default());
    });
    let h = rig
        .runner
        .start(rig.request(restore(true, false)))
        .await
        .unwrap();
    let out = rig.outcome(&h).await;
    assert!(out.result.is_ok(), "{:?}", out.result);
    assert_eq!(*verify.lock().unwrap(), Some(true));
    assert!(
        rig.host
            .log()
            .iter()
            .any(|l| l.contains(&format!("target=Some(\"{t}\") reuse=true"))),
        "{:?}",
        rig.host.log()
    );
    assert_eq!(rig.host.targets(), vec![t.to_string()]);
    assert_eq!(
        out.result.as_ref().unwrap().restore_target.as_deref(),
        Some(t)
    );
}

// ----- L1, L2 ----------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_completed_record_is_never_rewritten_and_blocks_only_a_prune() {
    let rig = Rig::ready().await;
    std::fs::create_dir_all(rig.desktop_dir()).unwrap();
    let p = rig.desktop_dir().join("completed.json");
    std::fs::write(&p, "{ corrupt").unwrap();
    rig.worker(snapshot_result);
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    assert!(
        rig.outcome(&h).await.result.is_ok(),
        "a backup does not read the record at admission"
    );
    assert_eq!(std::fs::read_to_string(&p).unwrap(), "{ corrupt");
    assert!(rig.audit().contains("cannot record the backup"));
    let e = rig
        .runner
        .start(rig.request(JobSpec::ForgetPrune {
            retention: Retention::EVERY_24H,
        }))
        .await
        .err()
        .unwrap();
    assert!(matches!(e, StartError::Record(_)), "{e:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_accepted_success_wins_over_a_violation_that_follows_it() {
    let rig = Rig::ready().await;
    rig.worker(|w| {
        let s = w.put(T::Snapshot, &body(10, 1));
        w.p.send(pb::repo_frame::Frame::Result(pb::JobResult {
            ok: true,
            snapshot_id: Bytes::copy_from_slice(&s),
            ..Default::default()
        }))
        .unwrap();
        // A frame after the result: a violation, written past the worker's own checks.
        let b = frame_bytes(
            pb::repo_frame::Frame::Progress(pb::Progress::default()),
            Endpoint::PrivdWorkerLink,
        );
        w.p.send_raw(&b);
        w.until_closed();
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    let out = rig.outcome(&h).await;
    assert!(out.result.is_ok(), "{:?}\n{}", out.result, rig.audit());
    assert_eq!(
        rig.runner.completed("main").unwrap().backups.len(),
        1,
        "the outcome and the record agree"
    );
}

// ----- L3, L4, L5, L6 ----------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_that_cannot_be_forwarded_is_answered_unavailable() {
    let rig = Rig::ready().await;
    let answers: Arc<Mutex<Vec<Option<Reply>>>> = Arc::default();
    let a2 = answers.clone();
    rig.worker(move |w| {
        for _ in 0..300 {
            let r = w.request(pb::repo_request::Op::List(pb::List {
                object_type: T::Config as i32,
            }));
            let got = w.try_wait(r);
            let stop = !matches!(got, Some(Reply::List(_)));
            a2.lock().unwrap().push(got);
            if stop {
                break;
            }
        }
        w.wait_cancel();
        w.finish_err(WorkerError::Cancelled);
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    running(&rig, &h).await;
    rig.drive.cmd.send(DriveCmd::Close).unwrap();
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::Unavailable);
    let last = answers.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        last,
        Some(Reply::Error(ErrorClass::Unavailable)),
        "the worker is always answered"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_admissions_cannot_clean_one_leftover_at_once() {
    let rig = Rig::ready().await;
    let left = "hx-backup-20261126T030000Z-aaaa";
    rig.host.add_snapshot("hx-main", left);
    write_job_record(
        &rig,
        "main",
        JobKind::Backup,
        job(4),
        None,
        false,
        Some(left),
    );
    rig.host.set_delete_delay_ms(60);
    rig.worker(|w| w.finish_ok(pb::JobResult::default()));
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let r = rig.runner.clone();
        let req = rig.request(JobSpec::Snapshots);
        tasks.push(tokio::spawn(
            async move { r.start(req).await.map(|h| h.job_id) },
        ));
    }
    let mut ok = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(_) => ok += 1,
            Err(e) => assert_eq!(e, StartError::Busy),
        }
    }
    assert_eq!(ok, 1);
    assert_eq!(
        rig.host.count(&format!("delete_snapshot hx-main {left}")),
        1,
        "the leftover was cleaned once, by the admission that held the slot"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancel_while_the_desktop_lock_is_awaited_is_cancelled_not_a_snapshot_failure() {
    let rig = Rig::ready().await;
    rig.env.hold_lock.store(true, Ordering::SeqCst);
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    rig.until("the lock wait", || {
        rig.env.locks.load(Ordering::SeqCst) == 1
    })
    .await;
    h.cancel();
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::Cancelled);
    assert_eq!(rig.host.count("create_snapshot"), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_auth_revoked_that_was_relayed_still_sets_the_flag_when_a_cancel_ends_the_job() {
    let rig = Rig::ready().await;
    rig.drive.knobs.lock().unwrap().list_error = Some(ErrorClass::AuthRevoked);
    let seen = Arc::new(AtomicBool::new(false));
    let s2 = seen.clone();
    rig.worker(move |w| {
        assert_eq!(w.list(T::Pack), Reply::Error(ErrorClass::AuthRevoked));
        s2.store(true, Ordering::SeqCst);
        w.wait_cancel();
        w.finish_err(WorkerError::Cancelled);
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    rig.until("the error", || seen.load(Ordering::SeqCst)).await;
    h.cancel();
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::Cancelled);
    assert!(
        rig.env.has_flag(None, Flag::DriveReconnect),
        "the repository's state counts"
    );
}

// ----- S-L4, S-L6, TOO_LARGE --------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_config_write_needs_a_new_empty_listing() {
    let rig = Rig::ready().await;
    rig.worker(|w| {
        assert_eq!(w.list(T::Config), Reply::List(vec![]));
        assert_eq!(w.write(T::Config, &[0u8; 32], b"first"), Reply::Done);
        let r = w.start_write(T::Config, &[0u8; 32], b"second");
        let _ = w.try_wait(r);
    });
    let mut req = rig.request(JobSpec::Init);
    req.new_key_password = Some(zeroizing(b"recovery-key-0123456789"));
    let h = rig.runner.start(req).await.unwrap();
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::PolicyDenied);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_first_permission_answer_is_audited_and_the_rest_are_counted() {
    let rig = Rig::ready().await;
    rig.drive.knobs.lock().unwrap().write_error_all = Some((T::Pack, ErrorClass::Permission));
    rig.worker(|w| {
        for i in 0..5u8 {
            let d = body(100, i);
            let id = sha(&d);
            assert_eq!(
                w.write(T::Pack, &id, &d),
                Reply::Error(ErrorClass::Permission)
            );
        }
        w.finish_err(WorkerError::Engine);
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    let out = rig.outcome(&h).await;
    assert_eq!(out.permission_answers, 5);
    let audit = rig.audit();
    assert_eq!(
        audit.matches("answered PERMISSION to").count(),
        1,
        "{audit}"
    );
    assert!(
        audit.contains("answered PERMISSION 5 times in all"),
        "{audit}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_over_the_size_cap_is_too_large_and_backs_off() {
    let rig = Rig::ready().await;
    rig.worker(|w| {
        let r = w.request(pb::repo_request::Op::Write(pb::Write {
            object_type: T::Pack as i32,
            id: Bytes::copy_from_slice(&[4u8; 32]),
            size: 73 * 1024 * 1024,
        }));
        let _ = w.try_wait(r);
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::TooLarge);
    assert!(
        !rig.drive
            .seen()
            .iter()
            .any(|s| matches!(s, Seen::Request(r) if r.starts_with("write")))
    );
    assert!(rig.desktop_dir().join("backoff.json").exists());
    assert!(rig.audit().contains("TOO_LARGE"));
}

// ----- nits ---------------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_job_that_does_not_fit_its_frame_is_refused_before_anything_exists_or_prune_is_split() {
    let rig = Rig::ready().await;
    let before = rig.host.log().len();
    // Excludes that do not fit: refused at admission.
    let big = BackupParams {
        excludes: vec!["a".repeat(1000); 256],
        ..BackupParams::default()
    };
    let e = rig
        .runner
        .start(rig.request(JobSpec::Backup(big)))
        .await
        .err()
        .unwrap();
    assert!(matches!(e, StartError::Invalid(_)), "{e:?}");
    assert_eq!(
        rig.host.log().len(),
        before,
        "nothing was created: {:?}",
        rig.host.log()
    );
    // A prune of 2 500 recorded backups names the 1 800 oldest.
    std::fs::create_dir_all(rig.desktop_dir()).unwrap();
    let mut rec = CompletedRecord::default();
    for i in 0..2500u32 {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&(i + 1).to_be_bytes());
        rec.add(CompletedBackup {
            snapshot_id: hex(&id),
            job_id: "0".repeat(32),
            time_unix: 1000 + u64::from(i),
            files_new: 0,
            files_changed: 0,
            files_unmodified: 0,
            bytes_processed: 0,
            bytes_added: 0,
            warnings: 0,
        });
    }
    // 2 500 > the record cap of 4 096? No: it fits. Keep only the floor.
    rec.store(&rig.desktop_dir().join("completed.json"))
        .unwrap();
    let named = Arc::new(Mutex::new(0usize));
    let n2 = named.clone();
    rig.worker(move |w| {
        let Some(pb::job::Spec::ForgetPrune(fp)) = &w.job.spec else {
            panic!()
        };
        *n2.lock().unwrap() = fp.forget.len();
        assert_eq!(&fp.forget[0][..4], &1u32.to_be_bytes(), "the oldest first");
        w.finish_ok(pb::JobResult::default());
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
    assert!(rig.outcome(&h).await.result.is_ok());
    assert_eq!(*named.lock().unwrap(), 1800);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_policy_applies_while_the_job_is_being_cancelled() {
    let rig = Rig::ready().await;
    rig.drive.put(T::Pack, &[5u8; 32], b"pack");
    rig.worker(|w| {
        w.wait_cancel();
        let r = w.request(pb::repo_request::Op::Remove(pb::Remove {
            object_type: T::Pack as i32,
            id: Bytes::copy_from_slice(&[5u8; 32]),
        }));
        let _ = w.try_wait(r);
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    running(&rig, &h).await;
    h.cancel();
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::PolicyDenied);
    assert!(rig.audit().contains("POLICY_DENIED"));
    assert!(rig.desktop_dir().join("backoff.json").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_job_closes_its_healthy_drive_session_with_bye() {
    let rig = Rig::ready().await;
    rig.worker(|w| {
        w.wait_cancel();
        w.finish_err(WorkerError::Cancelled);
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    running(&rig, &h).await;
    h.cancel();
    rig.outcome(&h).await;
    rig.until("Bye", || rig.drive.seen().contains(&Seen::Bye))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cleaning_up_phase_is_entered() {
    let rig = Rig::ready().await;
    let mono = rig.mono.clone();
    rig.host.set_on_finish(move |_| mono.advance_ms(300));
    let mono2 = rig.mono.clone();
    rig.worker(move |w| {
        mono2.advance_ms(300);
        snapshot_result(w);
    });
    let (ps, queue) = ProgressSender::new(1);
    let mut req = rig.backup_request();
    req.progress = Some(ps);
    let h = rig.runner.start(req).await.unwrap();
    assert!(rig.outcome(&h).await.result.is_ok());
    let mut steps = Vec::new();
    while let Some(f) = queue.pop() {
        steps.push(f.step);
    }
    assert!(steps.iter().any(|s| s == "Cleaning up"), "{steps:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proxy_that_accepts_and_closes_before_the_worker_listens_is_retried() {
    let rig = Rig::ready().await;
    let host = rig.host.clone();
    rig.host.set_on_start(move |info| {
        let host = host.clone();
        std::thread::spawn(move || {
            let mut w = WorkerPeer::accept_skipping(&info.socket, 2);
            snapshot_result(&mut w);
            drop(w);
            host.helper_exited(info.job);
        });
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    let out = rig.outcome(&h).await;
    assert!(out.result.is_ok(), "{:?}\n{}", out.result, rig.audit());
}

// ----- weak tests, strengthened -----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_end_of_the_stream_after_read_begin_without_an_event_is_unavailable_and_no_violation() {
    let rig = Rig::ready().await;
    rig.drive.put(T::Pack, &[9u8; 32], &body(2_000_000, 4));
    rig.drive.knobs.lock().unwrap().eof_reads = Some(0);
    rig.worker(|w| {
        w.request(pb::repo_request::Op::ReadFull(pb::ReadFull {
            object_type: T::Pack as i32,
            id: Bytes::copy_from_slice(&[9u8; 32]),
        }));
        w.wait_cancel();
        w.finish_err(WorkerError::Cancelled);
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    let out = rig.outcome(&h).await;
    assert_eq!(out.result.as_ref().unwrap_err(), &Failure::Unavailable);
    assert!(!rig.audit().contains("DRIVE_PROTOCOL"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_guard_holds_with_normal_ping_traffic_and_small_clock_steps() {
    let rig = Rig::ready().await;
    rig.drive.knobs.lock().unwrap().hold_lists = true;
    rig.worker(|w| {
        assert_eq!(w.list(T::Pack), Reply::List(vec![]));
        snapshot_result(w);
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    rig.until("the list request", || {
        rig.drive
            .seen()
            .iter()
            .any(|s| matches!(s, Seen::Request(r) if r.starts_with("list")))
    })
    .await;
    // 20 minutes in 10 s steps: pings go round every 15 s, nothing is silent, nothing is stale.
    rig.advance(20 * 60_000, 10_000).await;
    assert_ne!(h.status().state, JobState::Finished);
    rig.drive
        .cmd
        .send(DriveCmd::Event(pb::Event {
            kind: pb::EventKind::Retrying as i32,
            until_ms: 0,
            error_class: 0,
        }))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    rig.advance(20 * 60_000, 10_000).await;
    assert_ne!(
        h.status().state,
        JobState::Finished,
        "40 minutes in all, restarted by a sign of life"
    );
    rig.drive.knobs.lock().unwrap().hold_lists = false;
    assert!(rig.outcome(&h).await.result.is_ok());
}
