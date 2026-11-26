//! The job runner and the link backend against a fake privd (no Incus, no root).
//!
//! The worker's session runs in this process (the sandbox is off: it would apply to the test
//! harness), against a fake privd on a socket pair that applies the operation policy and the
//! SHA-256 check of every write, as privd will.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use common::*;
use hx_ipc::repo::pb::{self, ObjectType as T, WorkerError as W};
use sha2::{Digest, Sha256};

struct Env {
    _dir: tempfile::TempDir,
    root: PathBuf,
    store: SharedStore,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_owned();
        Self {
            _dir: dir,
            root,
            store: new_store(),
        }
    }
    fn cfg(&self) -> hx_backup_worker::session::WorkerConfig {
        config(&dirs(&self.root))
    }
    fn src(&self) -> PathBuf {
        self.root.join("src")
    }
    fn dst(&self) -> PathBuf {
        self.root.join("dst")
    }
    fn init(&self) -> pb::JobResult {
        run_ok(init_job(), &self.store, &self.cfg())
    }
    fn backup(&self) -> pb::JobResult {
        run_ok(backup_job(&[], &["nightly"]), &self.store, &self.cfg())
    }
}

fn sha256_hex(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}

#[test]
fn init_backup_snapshots_plan_restore_round_trip() {
    let env = Env::new();
    make_tree(&env.src());

    // INIT: a repository, two keys, sizes as the contract fixes them.
    let r = env.init();
    assert_eq!(r.key_ids.len(), 2);
    assert!(r.key_ids.iter().all(|k| k.len() == 32));
    assert_ne!(r.key_ids[0], r.key_ids[1]);
    {
        let st = env.store.lock().unwrap();
        assert!(st.created, "INIT must send Create");
        assert_eq!(st.count(T::Config), 1);
        assert_eq!(st.count(T::Key), 2);
        let key_ids: Vec<_> = st.ids(T::Key);
        for k in &r.key_ids {
            assert!(key_ids.contains(&k.to_vec()));
        }
    }

    // INIT again: refused before anything is written.
    let before = env.store.lock().unwrap().objects.len();
    let out = run_failing(init_job(), &env.store, &env.cfg(), W::RepositoryExists);
    assert!(
        out.ops.iter().all(|o| o.starts_with("List")),
        "{:?}",
        out.ops
    );
    assert_eq!(env.store.lock().unwrap().objects.len(), before);

    // BACKUP
    let b = env.backup();
    assert_eq!(b.snapshot_id.len(), 32);
    assert!(b.files_new >= 7, "{b:?}");
    assert!(b.bytes_processed >= 5 * 1024 * 1024);
    assert!(
        b.bytes_added > 5 * 1024 * 1024,
        "noise does not compress: {b:?}"
    );
    {
        let st = env.store.lock().unwrap();
        assert!(st.count(T::Pack) >= 1);
        assert_eq!(st.count(T::Snapshot), 1);
        assert!(st.ids(T::Snapshot).contains(&b.snapshot_id.to_vec()));
    }

    // SNAPSHOTS
    let s = run_ok(snapshots_job(), &env.store, &env.cfg());
    assert_eq!(s.snapshots.len(), 1);
    let info = &s.snapshots[0];
    assert_eq!(info.id, b.snapshot_id);
    assert_eq!(
        info.tags,
        vec!["nightly".to_owned()],
        "without the constant tag"
    );
    assert!(info.time > 1_700_000_000);
    assert!(info.size > 5 * 1024 * 1024);

    // RESTORE_PLAN: the manifest, and its digest is the one SNAPSHOTS reports
    let p = run_ok(restore_plan_job(&b.snapshot_id), &env.store, &env.cfg());
    let manifest = String::from_utf8(p.manifest.to_vec()).unwrap();
    assert!(manifest.contains("\"desktop\":\"xfce4\""), "{manifest}");
    assert!(manifest.contains("\"limits.cpu\":\"4\""));
    assert!(manifest.contains(&hex_of(&b.snapshot_id)));
    assert_eq!(
        info.manifest_digest.to_vec(),
        sha256_hex(manifest.as_bytes())
    );

    // RESTORE
    let before_objects = env.store.lock().unwrap().objects.len();
    run_ok(restore_job(&b.snapshot_id), &env.store, &env.cfg());
    assert_eq!(
        env.store.lock().unwrap().objects.len(),
        before_objects,
        "a restore writes nothing"
    );
    assert_same_tree(&env.src(), &env.dst());

    // A second backup of the unchanged tree adds no pack data to speak of.
    let b2 = env.backup();
    assert_eq!(b2.files_new, 0);
    assert!(b2.files_unmodified >= 7);
    assert!(b2.bytes_added < 100 * 1024, "{b2:?}");
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn a_wrong_password_and_a_missing_repository_are_told_apart() {
    let env = Env::new();
    make_tree(&env.src());

    // nothing there yet
    run_failing(snapshots_job(), &env.store, &env.cfg(), W::NoRepository);
    run_failing(
        backup_job(&[], &[]),
        &env.store,
        &env.cfg(),
        W::NoRepository,
    );
    assert!(env.store.lock().unwrap().objects.is_empty());

    env.init();
    let wrong = with_password(snapshots_job(), b"not the password at all, no");
    run_failing(wrong, &env.store, &env.cfg(), W::WrongPassword);
    let wrong = with_password(backup_job(&[], &[]), b"not the password at all, no");
    run_failing(wrong, &env.store, &env.cfg(), W::WrongPassword);
}

#[test]
fn a_snapshot_that_does_not_exist_and_a_source_that_does_not_exist() {
    let env = Env::new();
    make_tree(&env.src());
    env.init();
    env.backup();
    run_failing(
        restore_plan_job(&[0xab; 32]),
        &env.store,
        &env.cfg(),
        W::SnapshotNotFound,
    );
    run_failing(
        restore_job(&[0xab; 32]),
        &env.store,
        &env.cfg(),
        W::SnapshotNotFound,
    );
    let mut cfg = env.cfg();
    cfg.job.src = env.root.join("no-such-source");
    run_failing(backup_job(&[], &[]), &env.store, &cfg, W::SourceUnreadable);
}

#[test]
fn an_unreadable_file_makes_the_backup_partial_and_a_failure_without_a_snapshot_id() {
    if is_root() {
        eprintln!("skipped: root reads everything");
        return;
    }
    let env = Env::new();
    make_tree(&env.src());
    write(&env.src().join("home/user/secret"), b"x", 0o000);
    env.init();
    let out = run_failing(
        backup_job(&[], &[]),
        &env.store,
        &env.cfg(),
        W::SourceUnreadable,
    );
    assert!(out.result.unwrap().snapshot_id.is_empty());
    // the snapshot was written all the same (ipc.md §28)
    assert_eq!(env.store.lock().unwrap().count(T::Snapshot), 1);
    fs::set_permissions(
        env.src().join("home/user/secret"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
}

#[test]
fn a_target_that_cannot_be_written_is_target_unwritable() {
    if is_root() {
        eprintln!("skipped: root writes everywhere");
        return;
    }
    let env = Env::new();
    make_tree(&env.src());
    env.init();
    let b = env.backup();
    fs::create_dir_all(env.dst()).unwrap();
    fs::set_permissions(env.dst(), fs::Permissions::from_mode(0o500)).unwrap();
    run_failing(
        restore_job(&b.snapshot_id),
        &env.store,
        &env.cfg(),
        W::TargetUnwritable,
    );
    fs::set_permissions(env.dst(), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn check_passes_on_a_good_repository_and_fails_on_a_damaged_one() {
    let env = Env::new();
    make_tree(&env.src());
    env.init();
    env.backup();
    run_ok(check_job(0), &env.store, &env.cfg());
    run_ok(check_job(100), &env.store, &env.cfg());
    run_ok(check_job(30), &env.store, &env.cfg());

    // flip bytes in a pack: privd's hash check would never have accepted it, so the damage is
    // done behind its back
    {
        let mut st = env.store.lock().unwrap();
        let key = st
            .objects
            .keys()
            .find(|(t, _)| *t == T::Pack as i32)
            .cloned()
            .unwrap();
        let v = st.objects.get_mut(&key).unwrap();
        for i in (100..v.len()).step_by(997) {
            v[i] ^= 0xff;
        }
    }
    run_failing(check_job(100), &env.store, &env.cfg(), W::Engine);
}

#[test]
fn keys_add_a_key_then_remove_the_first() {
    let env = Env::new();
    make_tree(&env.src());
    let init = env.init();
    env.backup();
    let host_id = init.key_ids[0].to_vec();
    let recovery_id = init.key_ids[1].to_vec();

    // add a third key, opened with the recovery key (slot 0)
    let third = b"a third key for this repository, 7";
    let r = run_ok(keys_job(RECOVERY, Some(third), &[]), &env.store, &env.cfg());
    assert_eq!(r.key_ids.len(), 1);
    assert_eq!(env.store.lock().unwrap().count(T::Key), 3);
    // the new key opens the repository
    run_ok(
        with_password(snapshots_job(), third),
        &env.store,
        &env.cfg(),
    );

    // remove the host key, opened with the recovery key
    run_ok(
        keys_job(RECOVERY, None, std::slice::from_ref(&host_id)),
        &env.store,
        &env.cfg(),
    );
    assert_eq!(env.store.lock().unwrap().count(T::Key), 2);
    run_failing(snapshots_job(), &env.store, &env.cfg(), W::WrongPassword);
    run_ok(
        with_password(snapshots_job(), RECOVERY),
        &env.store,
        &env.cfg(),
    );

    // the key in use cannot be removed: the engine refuses
    run_failing(
        keys_job(RECOVERY, None, &[recovery_id]),
        &env.store,
        &env.cfg(),
        W::Engine,
    );
    // privd's policy only lets a spec's own ids go: the denied list stays empty above
}

#[test]
fn forget_prune_removes_exactly_the_named_snapshots_and_is_idempotent() {
    let env = Env::new();
    make_tree(&env.src());
    env.init();
    let first = env.backup();
    write(
        &env.src().join("home/user/new.bin"),
        &noise(9, 600_000),
        0o644,
    );
    let second = env.backup();
    assert_ne!(first.snapshot_id, second.snapshot_id);
    assert_eq!(env.store.lock().unwrap().count(T::Snapshot), 2);

    // an unknown id in the list is skipped; a snapshot that is not listed is never touched
    let unknown = vec![0x11u8; 32];
    let spec = forget_job(&[first.snapshot_id.to_vec(), unknown.clone()]);
    let (code, out) = session(spec, &env.store, Behavior::default(), &env.cfg());
    assert_eq!(code, 0);
    assert!(out.denied.is_empty(), "denied: {:?}", out.denied);
    assert!(out.result.unwrap().ok);
    {
        let st = env.store.lock().unwrap();
        assert_eq!(st.ids(T::Snapshot), vec![second.snapshot_id.to_vec()]);
    }
    // the survivor is still whole
    run_ok(restore_job(&second.snapshot_id), &env.store, &env.cfg());
    assert!(env.dst().join("home/user/new.bin").exists());
    run_ok(check_job(100), &env.store, &env.cfg());

    // again: nothing left to forget, still a success
    let (code, out) = session(
        forget_job(&[first.snapshot_id.to_vec()]),
        &env.store,
        Behavior::default(),
        &env.cfg(),
    );
    assert_eq!(code, 0);
    assert!(out.result.unwrap().ok);
}

#[test]
fn a_listing_in_small_pages_and_pings_in_the_middle_of_a_job() {
    let env = Env::new();
    make_tree(&env.src());
    env.init();
    for i in 0..4 {
        write(
            &env.src().join(format!("home/user/n{i}")),
            &noise(10 + i, 3000),
            0o644,
        );
        env.backup();
    }
    let (code, out) = session(
        snapshots_job(),
        &env.store,
        Behavior {
            list_page: Some(1),
            ping_every: Some(Duration::from_millis(15)),
            ..Behavior::default()
        },
        &env.cfg(),
    );
    assert_eq!(code, 0);
    assert!(out.worker_violations.is_empty());
    let r = out.result.unwrap();
    assert!(r.ok);
    assert_eq!(r.snapshots.len(), 4);
    assert!(
        r.snapshots.windows(2).all(|w| w[0].time <= w[1].time),
        "oldest first"
    );
    assert!(!out.pongs.is_empty(), "the worker must answer Ping");
    let mut sorted = out.pongs.clone();
    sorted.sort_unstable();
    assert_eq!(out.pongs, sorted, "Pong nonces echo the Pings in order");
}

#[test]
fn an_upload_that_privd_answers_with_an_error_is_aborted_and_closed_in_order() {
    let env = Env::new();
    make_tree(&env.src());
    env.init();
    let (code, out) = session(
        backup_job(&[], &[]),
        &env.store,
        Behavior {
            abort_pack_upload: Some(pb::ErrorClass::Transient),
            ..Behavior::default()
        },
        &env.cfg(),
    );
    // no violation of the stream rules (privd's own LinkState checks every frame, including the
    // END that closes the aborted upload), an orderly end, and a REPO failure
    assert!(
        out.worker_violations.is_empty(),
        "{:?}",
        out.worker_violations
    );
    assert_eq!(code, 0);
    let r = out.result.unwrap();
    assert!(!r.ok);
    assert_eq!(r.error, W::Repo as i32);
    assert!(out.bye);
    assert_eq!(
        env.store.lock().unwrap().count(T::Snapshot),
        0,
        "no snapshot without the pack"
    );
}

#[test]
fn a_repository_error_from_privd_is_reported_as_repo_but_not_found_is_not() {
    let env = Env::new();
    make_tree(&env.src());
    env.init();
    env.backup();
    let (code, out) = session(
        snapshots_job(),
        &env.store,
        Behavior {
            fail_list: Some((T::Snapshot, pb::ErrorClass::RateLimited)),
            ..Behavior::default()
        },
        &env.cfg(),
    );
    assert_eq!(code, 0);
    assert_eq!(out.result.unwrap().error, W::Repo as i32);
    // an empty CONFIG listing is not an error at all
    let env2 = Env::new();
    run_failing(snapshots_job(), &env2.store, &env2.cfg(), W::NoRepository);
}

#[test]
fn cancel_during_a_backup_ends_with_cancelled_inside_the_window_and_leaves_no_snapshot() {
    let env = Env::new();
    make_tree(&env.src());
    env.init();
    let (code, out) = session(
        backup_job(&[], &[]),
        &env.store,
        Behavior {
            cancel_on: Some(CancelOn::FirstPackWrite),
            ..Behavior::default()
        },
        &env.cfg(),
    );
    assert!(
        out.worker_violations.is_empty(),
        "{:?}",
        out.worker_violations
    );
    assert_eq!(code, 0);
    let r = out.result.clone().unwrap();
    assert!(!r.ok);
    assert_eq!(r.error, W::Cancelled as i32);
    assert!(out.bye);
    let took = out.result_at.unwrap() - out.cancel_sent_at.unwrap();
    assert!(
        took < hx_ipc::repo::CANCEL_GRACE,
        "JobResult {took:?} after Cancel"
    );
    // the pack in flight was completed (a stream cannot end early), no new write was started
    assert_eq!(env.store.lock().unwrap().count(T::Snapshot), 0);
}

#[test]
fn cancel_during_a_restore_sends_the_failed_result_while_a_download_is_still_running() {
    let env = Env::new();
    make_tree(&env.src());
    env.init();
    let b = env.backup();
    let (code, out) = session(
        restore_job(&b.snapshot_id),
        &env.store,
        Behavior {
            cancel_on: Some(CancelOn::FirstPackDownload),
            read_chunk: Some(64 * 1024),
            ..Behavior::default()
        },
        &env.cfg(),
    );
    // privd's LinkState accepted the failed JobResult with a download outstanding (ipc.md §26),
    // the held data was then delivered and discarded, and the worker said Bye after it
    assert!(
        out.worker_violations.is_empty(),
        "{:?}",
        out.worker_violations
    );
    assert_eq!(code, 0);
    let r = out.result.clone().unwrap();
    assert!(!r.ok);
    assert_eq!(r.error, W::Cancelled as i32);
    assert!(out.bye, "Bye after the discarded download ended");
    let took = out.result_at.unwrap() - out.cancel_sent_at.unwrap();
    assert!(took < hx_ipc::repo::CANCEL_GRACE, "{took:?}");
}

#[test]
fn a_protocol_violation_by_privd_ends_the_worker_with_72_and_no_result() {
    let env = Env::new();
    make_tree(&env.src());
    env.init();
    let (code, out) = session(
        snapshots_job(),
        &env.store,
        Behavior {
            violate: Some(Violation::DoneForUnknownRequest),
            ..Behavior::default()
        },
        &env.cfg(),
    );
    assert_eq!(code, hx_backup_worker::role::EXIT_PROTOCOL);
    assert!(out.result.is_none(), "no JobResult after a violation");
    assert!(!out.bye, "no Bye either");
}

#[test]
fn a_silent_privd_ends_the_worker_with_73() {
    let env = Env::new();
    let mut cfg = env.cfg();
    cfg.link.silence_timeout = Duration::from_millis(300);
    let started = Instant::now();
    let (code, out) = session(
        snapshots_job(),
        &env.store,
        Behavior {
            go_silent: true,
            ..Behavior::default()
        },
        &cfg,
    );
    assert_eq!(code, hx_backup_worker::role::EXIT_LINK_LOST);
    assert!(out.result.is_none());
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn progress_is_numbers_only_and_at_most_two_a_second() {
    let env = Env::new();
    make_tree(&env.src());
    // enough data that the backup runs for a couple of seconds in a debug build
    for i in 0..6 {
        write(
            &env.src().join(format!("data/f{i}")),
            &noise(100 + i, 4 * 1024 * 1024),
            0o644,
        );
    }
    env.init();
    let (code, out) = session(
        backup_job(&[], &[]),
        &env.store,
        Behavior::default(),
        &env.cfg(),
    );
    assert_eq!(code, 0);
    assert!(out.result.unwrap().ok);
    let times: Vec<Instant> = out.progress.iter().map(|(t, _)| *t).collect();
    assert!(!times.is_empty(), "a backup reports progress");
    for w in times.windows(2) {
        assert!(
            w[1] - w[0] >= Duration::from_millis(400),
            "two Progress frames {:?} apart",
            w[1] - w[0]
        );
    }
    for (_, p) in &out.progress {
        assert!(
            pb::ProgressPhase::try_from(p.phase).is_ok_and(|p| p != pb::ProgressPhase::Unspecified)
        );
    }
}

#[test]
fn nothing_the_worker_sends_is_free_text() {
    let env = Env::new();
    make_tree(&env.src());
    let (_, out) = session(init_job(), &env.store, Behavior::default(), &env.cfg());
    let sw = out.software.clone().unwrap();
    assert!(
        (1..=64).contains(&sw.len())
            && sw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)),
        "{sw}"
    );
    let (_, out2) = session(
        backup_job(&[], &["nightly", "daily"]),
        &env.store,
        Behavior::default(),
        &env.cfg(),
    );
    let (_, out3) = session(snapshots_job(), &env.store, Behavior::default(), &env.cfg());
    for (i, out) in [out, out2, out3].iter().enumerate() {
        for f in &out.frames {
            // The only strings that can leave a worker: HelloAck.software and snapshot tags.
            // Everything else in the schema is a number, an enum or an id.
            if let Some(pb::repo_frame::Frame::Result(r)) = &f.frame {
                for s in &r.snapshots {
                    for t in &s.tags {
                        assert!(
                            (1..=64).contains(&t.len())
                                && t.bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                            "run {i}: tag {t:?}"
                        );
                    }
                }
                if !r.ok {
                    assert!(r.snapshots.is_empty() && r.manifest.is_empty());
                }
            }
        }
    }
}

#[test]
fn a_corrupt_pack_makes_rustic_panic_in_restore_and_the_job_still_ends_with_a_result() {
    let env = Env::new();
    make_tree(&env.src());
    env.init();
    let b = env.backup();
    {
        let mut st = env.store.lock().unwrap();
        let keys: Vec<_> = st
            .objects
            .keys()
            .filter(|(t, _)| *t == T::Pack as i32)
            .cloned()
            .collect();
        for k in keys {
            let v = st.objects.get_mut(&k).unwrap();
            for i in (0..v.len()).step_by(61) {
                v[i] ^= 0xa5;
            }
        }
    }
    let out = run_failing(
        restore_job(&b.snapshot_id),
        &env.store,
        &env.cfg(),
        W::Engine,
    );
    assert!(out.bye, "an orderly end, not a crash");
}

#[test]
fn a_damaged_index_ends_every_kind_of_job_with_a_result() {
    let env = Env::new();
    make_tree(&env.src());
    env.init();
    env.backup();
    {
        let mut st = env.store.lock().unwrap();
        let keys: Vec<_> = st
            .objects
            .keys()
            .filter(|(t, _)| *t == T::Index as i32)
            .cloned()
            .collect();
        assert!(!keys.is_empty());
        for k in keys {
            let v = st.objects.get_mut(&k).unwrap();
            for i in (0..v.len()).step_by(13) {
                v[i] ^= 0x5a;
            }
        }
    }
    for j in [check_job(0), forget_job(&[])] {
        let (code, out) = session(j, &env.store, Behavior::default(), &env.cfg());
        assert_eq!(code, 0, "{:?}", out.worker_violations);
        assert!(!out.result.expect("a JobResult").ok);
        assert!(out.bye);
    }
}
