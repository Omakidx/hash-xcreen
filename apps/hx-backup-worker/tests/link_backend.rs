//! `LinkBackend` driven directly from many threads, as rustic's pool drives it, against a slow fake
//! privd: the 8-request and 4-write limits of ipc.md §25 block the callers and are never violated
//! (privd's own `LinkState` checks every frame).

mod common;

use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use hx_backup::engine::{FileType, Link, LinkOptions, ReadBackend, WriteBackend};
use hx_ipc::repo::pb::{self, ObjectType as T};
use sha2::{Digest, Sha256};

#[test]
fn many_threads_never_exceed_eight_requests_or_four_writes() {
    let store = new_store();
    // objects to read
    {
        let mut st = store.lock().unwrap();
        for i in 0..6u8 {
            st.objects
                .insert((T::Pack as i32, vec![i + 1; 32]), vec![i; 300_000]);
        }
    }
    let (worker_end, privd_end) = UnixStream::pair().unwrap();
    let j = backup_job(&[], &[]);
    let fake = Fake::new(
        privd_end,
        j.job,
        j.secrets,
        Arc::clone(&store),
        Behavior {
            answer_delay: Some(Duration::from_millis(3)),
            defer_reads: true,
            ..Behavior::default()
        },
    );
    let fake = std::thread::spawn(move || fake.run());

    let (link, _start) = Link::accept(worker_end, "test-1.0", LinkOptions::default()).unwrap();
    link.start().unwrap();
    let backend = Arc::new(link.backend());
    let mut threads = Vec::new();
    for t in 0..24u32 {
        let be = Arc::clone(&backend);
        threads.push(std::thread::spawn(move || {
            for n in 0..6u32 {
                if (t + n) % 2 == 0 {
                    // a write: size varies, includes a multi-frame one
                    let body = vec![(t * 7 + n) as u8; 100_000 + (t as usize) * 40_000];
                    let id = Sha256::digest(&body);
                    let id = <[u8; 32]>::try_from(id.as_slice()).unwrap();
                    let id = rustic_id(id);
                    be.write_bytes(FileType::Pack, &id, false, body.into())
                        .unwrap();
                } else {
                    let i = (t as usize + n as usize) % 6;
                    let id = rustic_id([i as u8 + 1; 32]);
                    let got = be.read_full(FileType::Pack, &id).unwrap();
                    assert_eq!(got.len(), 300_000);
                    let part = be
                        .read_partial(FileType::Pack, &id, false, 10, 1000)
                        .unwrap();
                    assert_eq!(part.len(), 1000);
                }
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }
    link.finish(pb::JobResult {
        ok: false,
        error: pb::WorkerError::Engine as i32,
        ..Default::default()
    })
    .unwrap();
    let out = fake.join().unwrap();
    assert!(
        out.worker_violations.is_empty(),
        "{:?}",
        out.worker_violations
    );
    assert!(out.bye);
    assert!(out.max_outstanding <= 8, "{}", out.max_outstanding);
    assert!(out.max_writes <= 4, "{}", out.max_writes);
    assert!(
        out.max_outstanding >= 6,
        "the test must actually load the link: {}",
        out.max_outstanding
    );
}

fn rustic_id(b: [u8; 32]) -> hx_backup::engine::Id {
    hx_backup::engine::Id::new(b)
}

/// Four-plus parallel uploads, one of them aborted by privd while the writer's queue is busy with
/// the others: the closing `END` must be queued before the slot is freed, or a woken request overtakes
/// it and privd sees a ninth request or a fifth write.
#[test]
fn an_aborted_upload_frees_its_slot_only_after_its_end_is_queued() {
    for round in 0..3u8 {
        let store = new_store();
        let (worker_end, privd_end) = UnixStream::pair().unwrap();
        let j = backup_job(&[], &[]);
        let fake = Fake::new(
            privd_end,
            j.job,
            j.secrets,
            Arc::clone(&store),
            Behavior {
                abort_pack_upload: Some(pb::ErrorClass::Transient),
                ..Behavior::default()
            },
        );
        let fake = std::thread::spawn(move || fake.run());
        let (link, _start) = Link::accept(worker_end, "test-1.0", LinkOptions::default()).unwrap();
        link.start().unwrap();
        let backend = Arc::new(link.backend());
        let mut threads = Vec::new();
        for t in 0..16u32 {
            let be = Arc::clone(&backend);
            threads.push(std::thread::spawn(move || {
                let mut errors = 0;
                for n in 0..4u32 {
                    let body =
                        vec![(t * 5 + n) as u8 + round; 3 * 1024 * 1024 + (t as usize) * 1000];
                    let id = Sha256::digest(&body);
                    let id = rustic_id(<[u8; 32]>::try_from(id.as_slice()).unwrap());
                    if be
                        .write_bytes(FileType::Pack, &id, false, body.into())
                        .is_err()
                    {
                        errors += 1;
                    }
                    // requests right behind the uploads, to overtake a late END
                    let _ = be.list_with_size(FileType::Index);
                }
                errors
            }));
        }
        let errors: u32 = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert_eq!(errors, 1, "exactly the one aborted upload fails");
        link.finish(pb::JobResult {
            ok: false,
            error: pb::WorkerError::Engine as i32,
            ..Default::default()
        })
        .unwrap();
        let out = fake.join().unwrap();
        assert!(
            out.worker_violations.is_empty(),
            "round {round}: {:?}",
            out.worker_violations
        );
        assert!(out.max_outstanding <= 8 && out.max_writes <= 4);
    }
}
