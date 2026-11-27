//! The job runner end to end (ipc.md Part 3, sections 24 to 33): a fake worker and a fake Drive
//! helper speak the repository link over real unix sockets, the host is a fake, and time is a
//! manual monotonic clock. No Incus, no systemd, no network, no real key.

mod backup_common;

use std::sync::{Arc, Mutex};

use backup_common::*;
use bytes::Bytes;
use hx_agent::privd::backup::runner::StartError;
use hx_agent::privd::backup::spec::JobSpec;
use hx_agent::privd::backup::{Failure, JobState};
use hx_agent::privd::progress::ProgressSender;
use hx_ipc::repo::pb::{self, ErrorClass, ObjectType as T, ProgressPhase as P};

fn mt() -> bool {
    true
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_backup_round_trip() {
    let rig = Rig::ready().await;
    rig.drive.put(T::Config, &[0u8; 32], b"repository-config");
    type Sent = Option<(pb::Job, Vec<(u8, Vec<u8>)>)>;
    let sent: Arc<Mutex<Sent>> = Arc::default();
    let sent2 = sent.clone();
    let mono = rig.mono.clone();
    rig.worker(move |w| {
        *sent2.lock().unwrap() = Some((w.job.clone(), w.secrets.clone()));
        // Every clock step and every Progress frame is followed by a round trip, so that privd
        // has handled the one before the next step moves the clock.
        let sync = |w: &mut WorkerPeer| {
            assert!(matches!(w.list(T::Config), Reply::List(_)));
        };
        sync(w);
        mono.advance_ms(150);
        sync(w);
        w.progress(P::RepairIndex, 0, 0);
        sync(w);
        let Reply::List(v) = w.list(T::Config) else {
            panic!("config list")
        };
        assert_eq!(v.len(), 1);
        let pack = w.put(T::Pack, &body(1_500_000, 1)); // two data frames
        let _index = w.put(T::Index, &body(300, 2));
        sync(w);
        mono.advance_ms(150);
        sync(w);
        w.progress(P::ScanAndUpload, 50, 100);
        sync(w);
        let snap = w.put(T::Snapshot, &body(500, 3));
        assert_eq!(w.read(T::Pack, &pack), Reply::Read(body(1_500_000, 1)));
        sync(w);
        mono.advance_ms(150);
        sync(w);
        w.progress(P::WriteSnapshot, 0, 0);
        sync(w);
        w.finish_ok(pb::JobResult {
            snapshot_id: Bytes::copy_from_slice(&snap),
            files_new: 5,
            files_changed: 2,
            files_unmodified: 90,
            bytes_processed: 123_456,
            bytes_added: 7_890,
            entries_unreadable: 3,
            ..Default::default()
        });
    });
    let (ps, queue) = ProgressSender::new(7);
    let mut req = rig.backup_request();
    req.progress = Some(ps);
    let h = rig.runner.start(req).await.unwrap();
    let out = rig.outcome(&h).await;
    let ok = out
        .result
        .as_ref()
        .unwrap_or_else(|e| panic!("{e:?}\n{}", rig.audit()));
    let snap_id = ok.result.snapshot_id.to_vec();
    // privd's own count of the object bytes it relayed, both directions, exactly what the fake
    // peers moved: the pack (1 500 000), the index (300) and the snapshot (500) up, the pack
    // (1 500 000) down.
    assert_eq!(out.transfer_bytes, 3_000_800);
    assert_eq!(h.status().state, JobState::Finished);

    // The repository got the objects, each under its own hash.
    assert_eq!(rig.drive.objects(T::Pack).len(), 1);
    assert_eq!(rig.drive.objects(T::Index).len(), 1);
    assert_eq!(rig.drive.objects(T::Snapshot), vec![snap_id.clone()]);
    // The Drive session opened the repository with privd's constants, not the worker's.
    let opens = rig.drive.opens.lock().unwrap().clone();
    assert_eq!(opens.len(), 1);
    assert!(!opens[0].create && !opens[0].takeover);
    assert_eq!(opens[0].server_id.len(), 16);
    assert!(opens[0].folder.starts_with("hx-") && opens[0].folder.ends_with("-main"));
    // The worker was given the host's backup key as slot 0, and a job built from privd's facts.
    let (job, secrets) = sent.lock().unwrap().clone().unwrap();
    assert_eq!(secrets, vec![(0, KEY.to_vec())]);
    assert_eq!(job.kind, pb::JobKind::Backup as i32);
    let Some(pb::job::Spec::Backup(b)) = &job.spec else {
        panic!("not a backup spec")
    };
    assert!(b.tags[0].starts_with("hx-backup-"));
    assert_eq!(
        b.manifest.as_ref().unwrap().distro.as_ref().unwrap().id,
        "ubuntu"
    );
    // The completed-backups record has the backup, with the unreadable entries as a warning.
    let rec = rig.runner.completed("main").unwrap();
    assert_eq!(rec.backups.len(), 1);
    assert_eq!(rec.backups[0].snapshot_id, hex(&snap_id));
    assert_eq!((rec.backups[0].warnings, rec.backups[0].files_new), (3, 5));
    assert_eq!(rec.backups[0].time_unix, 1_800_000_000);
    // Everything privd made is gone; the slot is free.
    let log = rig.host.log();
    let pos = |p: &str| {
        log.iter()
            .position(|l| l.starts_with(p))
            .unwrap_or_else(|| panic!("{p} in {log:?}"))
    };
    assert!(pos("create_snapshot") < pos("create_helper"));
    assert!(pos("create_helper") < pos("start_helper"));
    assert!(pos("start_helper") < pos("finish_helper"));
    assert!(pos("finish_helper") < pos("delete_snapshot"));
    assert!(
        !log.iter().any(|l| l.starts_with("force_delete")),
        "{log:?}"
    );
    assert!(rig.host.helpers().is_empty());
    assert!(rig.host.snapshots("hx-main").is_empty());
    assert_eq!(
        std::fs::read_dir(&rig.cfg.run_dir).unwrap().count(),
        0,
        "the socket is removed"
    );
    assert!(!rig.desktop_dir().join("job.json").exists());
    let again = rig.runner.start(rig.backup_request()).await.unwrap();
    rig.outcome(&again).await;
    // No job is running: every relay slot is back, exactly 16 of them.
    rig.until("the relay slots to come back", || {
        rig.runner.relay_slots_free() == 16
    })
    .await;
    // Progress: privd's own text, privd's phase table, the byte counters.
    let mut frames = Vec::new();
    while let Some(f) = queue.pop() {
        frames.push(f);
    }
    // Which frames exist depends on the 100 ms throttle and on when a tick ran, so only their
    // invariants are asserted here; the numbers are asserted on the mapper itself
    // (progress.rs, deterministic).
    assert!(!frames.is_empty(), "{frames:?}");
    let table = [
        "Taking a snapshot",
        "Starting the backup worker",
        "Repairing the index",
        "Scanning and uploading",
        "Writing the snapshot",
        "Cleaning up",
    ];
    for f in &frames {
        assert_eq!(f.request_id, 7);
        assert_eq!(f.total, 6);
        assert_eq!(f.step, table[f.index as usize - 1], "{f:?}");
        assert_eq!(f.stage, hx_ipc::privd::pb::ProgressStage::Backup as i32);
    }
    // The audit log names the job and the end, and holds no secret.
    let audit = rig.audit();
    assert!(
        audit.contains("backup job started") && audit.contains("backup job finished"),
        "{audit}"
    );
    assert!(!audit.contains(std::str::from_utf8(KEY).unwrap()));
    assert!(mt());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_restore_plan_round_trip_and_an_untrusted_manifest() {
    for (honest, expect_ok) in [(true, true), (false, false)] {
        let rig = Rig::ready().await;
        let snap = [0x42u8; 32];
        rig.drive.put(T::Config, &[0u8; 32], b"cfg");
        rig.drive.put(T::Snapshot, &snap, b"snapshot-object");
        rig.worker(move |w| {
            w.progress(P::Plan, 0, 0);
            assert_eq!(
                w.read(T::Snapshot, &snap),
                Reply::Read(b"snapshot-object".to_vec())
            );
            // A dishonest worker names another snapshot in the manifest.
            let named = if honest {
                hex(&snap)
            } else {
                hex(&[0x43u8; 32])
            };
            w.finish_ok(pb::JobResult {
                manifest: Bytes::from(manifest_json(&named)),
                ..Default::default()
            });
        });
        let h = rig
            .runner
            .start(rig.request(JobSpec::RestorePlan { snapshot_id: snap }))
            .await
            .unwrap();
        let out = rig.outcome(&h).await;
        assert_eq!(
            out.result.is_ok(),
            expect_ok,
            "{:?}\n{}",
            out.result,
            rig.audit()
        );
        if let Ok(ok) = &out.result {
            assert!(!ok.result.manifest.is_empty());
        }
        // A repository-only job has no snapshot and no mount.
        assert!(rig.host.log().iter().any(|l| l.contains("RepositoryOnly")));
        assert_eq!(rig.host.count("create_snapshot"), 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn progress_is_throttled_to_ten_a_second_and_carries_only_privds_text() {
    let rig = Rig::ready().await;
    let mono = rig.mono.clone();
    rig.worker(move |w| {
        // 100 updates in one second of clock time, one every 10 ms.
        for i in 0..100u64 {
            mono.advance_ms(10);
            w.progress(P::ScanAndUpload, i, 100);
            // A round trip: privd has handled the progress frame before the clock moves again.
            w.list(T::Config);
        }
        let snap = w.put(T::Snapshot, &body(100, 9));
        w.finish_ok(pb::JobResult {
            snapshot_id: Bytes::copy_from_slice(&snap),
            ..Default::default()
        });
    });
    let (ps, queue) = ProgressSender::new(1);
    let mut req = rig.backup_request();
    req.progress = Some(ps);
    let h = rig.runner.start(req).await.unwrap();
    rig.outcome(&h).await;
    let mut n = 0;
    let mut scan = 0;
    while let Some(f) = queue.pop() {
        n += 1;
        if f.step == "Scanning and uploading" {
            scan += 1;
        }
        assert!(
            [
                "Taking a snapshot",
                "Starting the backup worker",
                "Repairing the index",
                "Scanning and uploading",
                "Writing the snapshot",
                "Cleaning up"
            ]
            .contains(&f.step.as_str()),
            "{}",
            f.step
        );
    }
    // 100 updates over 1.0 s of the monotonic clock: at most 10 frames for them (plus the
    // frames of the phases privd runs itself).
    assert!(scan <= 11, "{scan} scan frames");
    assert!(scan >= 8, "the throttle must not starve the stream: {scan}");
    assert!(n < 20, "{n} frames in all");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_job_is_refused_while_the_slot_is_held() {
    let rig = Rig::ready().await;
    let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let r2 = release.clone();
    rig.worker(move |w| {
        w.poll_every(std::time::Duration::from_millis(10));
        while !r2.load(std::sync::atomic::Ordering::SeqCst) {
            if w.pump().is_err() {
                return;
            }
        }
        let snap = w.put(T::Snapshot, &body(10, 1));
        w.finish_ok(pb::JobResult {
            snapshot_id: Bytes::copy_from_slice(&snap),
            ..Default::default()
        });
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    // Held: a second job of any kind is refused, nothing is queued, nothing is created.
    let before = rig.host.log().len();
    for spec in [
        JobSpec::Snapshots,
        JobSpec::Check {
            read_data_percent: 0,
        },
    ] {
        let e = rig.runner.start(rig.request(spec)).await.err().unwrap();
        assert_eq!(e, StartError::Busy);
    }
    assert!(h.status().state != JobState::Finished);
    assert_eq!(
        rig.host.log().len(),
        before,
        "a refused job touches nothing"
    );
    release.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(rig.outcome(&h).await.result.is_ok());
    assert!(
        rig.runner
            .start(rig.request(JobSpec::Snapshots))
            .await
            .is_ok()
    );
    let _ = (Failure::Cancelled, ErrorClass::Internal);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_job_is_admitted_before_recovery_and_a_missing_token_starts_nothing() {
    let rig = Rig::raw();
    let e = rig.runner.start(rig.backup_request()).await.err().unwrap();
    assert_eq!(e, StartError::Recovering);
    assert_eq!(rig.host.log().len(), 0);
    assert!(rig.runner.recover().await.complete);
    // The token credential is missing: privd sets DRIVE_RECONNECT itself and starts nothing.
    std::fs::remove_file(&rig.cfg.drive_cred).unwrap();
    let before = rig.host.log().len();
    let e = rig.runner.start(rig.backup_request()).await.err().unwrap();
    assert_eq!(e, StartError::DriveReconnect);
    assert!(
        rig.env
            .has_flag(None, hx_agent::privd::state::Flag::DriveReconnect)
    );
    assert_eq!(rig.host.log().len(), before, "nothing was created");
    assert!(!rig.desktop_dir().join("job.json").exists());
    assert_eq!(
        *rig.drive.connections.lock().unwrap(),
        0,
        "the Drive helper was not contacted"
    );
    // With the token back the job is admitted.
    std::fs::write(&rig.cfg.drive_cred, b"sealed").unwrap();
    rig.worker(|w| {
        let s = w.put(T::Snapshot, &body(10, 1));
        w.finish_ok(pb::JobResult {
            snapshot_id: Bytes::copy_from_slice(&s),
            ..Default::default()
        });
    });
    let h = rig.runner.start(rig.backup_request()).await.unwrap();
    assert!(rig.outcome(&h).await.result.is_ok());
}
