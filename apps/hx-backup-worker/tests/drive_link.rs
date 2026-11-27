//! The Drive helper's link session against a fake Google: the object operations of ipc.md §27 and
//! the rules of §29 that are not about errors (those are in `drive_errors.rs`, the lease in
//! `drive_lease.rs`, the process in `drive_process.rs`).

mod drive_common;

use std::time::{Duration, Instant};

use drive_common::*;
use hx_backup_worker::drive::server::End;
use hx_ipc::repo::pb;

#[test]
fn a_full_round_trip_over_the_link_with_permanent_deletes_and_lazy_folders() {
    let rig = Rig::new();
    let mut s = rig.session();
    s.env.hello();
    assert!(
        s.env
            .software
            .as_deref()
            .unwrap()
            .starts_with("hx-backup-worker-")
    );
    s.env.open("repo", true, SERVER_A, false).ok();
    // an empty repository: no config, nothing listed
    assert_eq!(s.env.list(T::Config), Reply::List(vec![]));
    assert_eq!(s.env.list(T::Pack), Reply::List(vec![]));
    s.env.create().ok();
    rig.fake.with(|m| {
        for d in ["repo/keys/", "repo/snapshots/", "repo/index/", "repo/data/"] {
            assert!(m.paths().contains(&d.to_owned()), "{d} in {:?}", m.paths());
        }
        assert!(
            !m.paths()
                .iter()
                .any(|p| p.starts_with("repo/data/") && p != "repo/data/"),
            "no data/xx folder exists before a pack is written"
        );
    });

    let config = data(300, 1);
    let key = data(500, 2);
    let snap = data(2000, 3);
    let index = data(70_000, 4);
    let packs: Vec<([u8; 32], Vec<u8>)> = (0..3u8)
        .map(|i| {
            (
                id(0x10 + i * 0x20),
                data(300_000 + usize::from(i) * 1000, 10 + i),
            )
        })
        .collect();
    s.env.write(T::Config, &[0; 32], &config).ok();
    s.env.write(T::Key, &id(1), &key).ok();
    s.env.write(T::Snapshot, &id(2), &snap).ok();
    s.env.write(T::Index, &id(3), &index).ok();
    for (i, body) in &packs {
        s.env.write(T::Pack, i, body).ok();
    }
    // the layout of restic, and only the data folders that were written to
    rig.fake.with(|m| {
        assert_eq!(m.get("repo/config").unwrap(), config);
        assert_eq!(m.get(&path_of(T::Key, &id(1))).unwrap(), key);
        assert_eq!(m.get(&path_of(T::Snapshot, &id(2))).unwrap(), snap);
        assert_eq!(m.get(&path_of(T::Index, &id(3))).unwrap(), index);
        let dirs: Vec<_> = m
            .paths()
            .into_iter()
            .filter(|p| p.starts_with("repo/data/") && p.ends_with('/'))
            .collect();
        assert_eq!(
            dirs,
            [
                "repo/data/",
                "repo/data/10/",
                "repo/data/30/",
                "repo/data/50/"
            ]
        );
    });

    // listings
    assert_eq!(s.env.list(T::Config), Reply::List(vec![(vec![0; 32], 300)]));
    assert_eq!(s.env.list(T::Key), Reply::List(vec![(id(1).to_vec(), 500)]));
    let Reply::List(mut got) = s.env.list(T::Pack) else {
        panic!()
    };
    got.sort();
    let want: Vec<(Vec<u8>, u32)> = packs
        .iter()
        .map(|(i, b)| (i.to_vec(), b.len() as u32))
        .collect();
    assert_eq!(got, want);

    // reads: whole objects (config, a pack) and ranges
    assert_eq!(
        s.env.read_full(T::Config, &[0; 32]),
        Reply::Read(config.clone())
    );
    assert_eq!(
        s.env.read_full(T::Index, &id(3)),
        Reply::Read(index.clone())
    );
    let (pid, pbody) = &packs[1];
    assert_eq!(s.env.read_full(T::Pack, pid), Reply::Read(pbody.clone()));
    for (off, len) in [
        (0u32, 1u32),
        (0, 4096),
        (12_345, 70_000),
        (pbody.len() as u32 - 100, 100),
    ] {
        let want = pbody[off as usize..(off + len) as usize].to_vec();
        assert_eq!(
            s.env.read_partial(T::Pack, pid, off, len),
            Reply::Read(want),
            "{off}+{len}"
        );
    }
    // a read of an object that is not there
    assert_eq!(
        s.env.read_full(T::Pack, &id(0x77)).class(),
        Some(EC::NotFound)
    );

    // overwriting an object is allowed (a retry after an ambiguous failure does this)
    let again = data(300_500, 99);
    s.env.write(T::Pack, &packs[0].0, &again).ok();
    assert_eq!(s.env.read_full(T::Pack, &packs[0].0), Reply::Read(again));

    // removing: permanently, and an absent object is not an error
    s.env.remove(T::Pack, &packs[2].0).ok();
    s.env.remove(T::Pack, &packs[2].0).ok();
    s.env.remove(T::Pack, &id(0x78)).ok();
    s.env.remove(T::Index, &id(3)).ok();
    rig.fake.with(|m| {
        assert!(m.get(&path_of(T::Pack, &packs[2].0)).is_none());
        assert!(m.get(&path_of(T::Index, &id(3))).is_none());
        assert_eq!(
            m.count("trash"),
            0,
            "OpenDAL's trash request must never reach Drive"
        );
        assert_eq!(m.trashed_count(), 0);
        assert!(m.count("delete") >= 2, "DELETE files/{{id}}");
    });
    assert_eq!(s.finish(), End::Bye);
}

#[test]
fn concurrent_writes_to_one_new_data_folder_create_it_once() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    // four writes (the link's limit) whose ids share a first byte
    let mut reqs = vec![];
    let bodies: Vec<Vec<u8>> = (0..4).map(|i| data(50_000, i)).collect();
    for (i, body) in bodies.iter().enumerate() {
        let mut pid = id(0xab);
        pid[1] = i as u8;
        let r = s.env.request(pb::repo_request::Op::Write(pb::Write {
            object_type: T::Pack as i32,
            id: bytes::Bytes::copy_from_slice(&pid),
            size: body.len() as u32,
        }));
        reqs.push((r, pid, body));
    }
    for (r, _, body) in &reqs {
        s.env.upload(*r, body);
    }
    for (r, _, _) in &reqs {
        assert_eq!(s.env.wait(*r), Reply::Done);
    }
    rig.fake.with(|m| {
        let n = m.paths().iter().filter(|p| *p == "repo/data/ab/").count();
        assert_eq!(
            n,
            1,
            "one data/ab folder, not one per concurrent write: {:?}",
            m.paths()
        );
        for (_, pid, body) in &reqs {
            assert_eq!(&m.get(&path_of(T::Pack, pid)).unwrap(), *body);
        }
    });
}

#[test]
fn listings_skip_what_is_not_an_object_and_page_at_1024_entries() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    rig.fake.with(|m| {
        for i in 0..2500u32 {
            let mut pid = [0u8; 32];
            pid[..4].copy_from_slice(&(i + 1).to_be_bytes());
            m.put(&format!("repo/index/{}", hex(&pid)), &[1, 2, 3]);
        }
        m.put("repo/index/not-an-id", b"x");
        m.put(&format!("repo/index/{}", "0".repeat(64)), b"x"); // the zero id is no object
        m.put(&format!("repo/index/{}", "AB".repeat(32)), b"x"); // ids are lower-case
        m.put("repo/index/sub/inner", b"x");
        // Drive itself pages the listing
        m.force_page_size = 700;
    });
    let r = s.env.request(pb::repo_request::Op::List(pb::List {
        object_type: T::Index as i32,
    }));
    let Reply::List(entries) = s.env.wait(r) else {
        panic!()
    };
    assert_eq!(entries.len(), 2500);
    assert_eq!(s.env.pages_seen, 3, "1024 + 1024 + 452");
    let mut ids: Vec<_> = entries.iter().map(|e| e.0.clone()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 2500);
    assert!(entries.iter().all(|e| e.1 == 3));
}

#[test]
fn a_failed_listing_page_is_an_error_and_never_a_truncated_list() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    rig.fake.with(|m| {
        for i in 0..5u8 {
            m.put(&format!("repo/index/{}", hex(&id(i + 1))), &[i]);
        }
        m.force_page_size = 2;
        m.fail_continuations = true;
    });
    let before = s.env.pages_seen;
    let r = s.env.list(T::Index);
    assert_eq!(r.class(), Some(EC::Transient), "{r:?}");
    assert_eq!(
        s.env.pages_seen, before,
        "no page of a failed listing is ever sent"
    );
    // and the session is still usable
    rig.fake.with(|m| m.fail_continuations = false);
    assert!(matches!(s.env.list(T::Index), Reply::List(v) if v.len() == 5));
}

#[test]
fn a_ranged_read_that_is_not_fully_answered_is_internal_and_not_retried() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    s.env.write(T::Pack, &id(0x40), &data(1000, 5)).ok();
    let gets = rig.fake.with(|m| m.count("get.media"));
    // 900 + 200 runs past the end: Drive answers 900..999 only
    let r = s.env.read_partial(T::Pack, &id(0x40), 900, 200);
    assert_eq!(r.class(), Some(EC::Internal), "{r:?}");
    assert_eq!(
        rig.fake.with(|m| m.count("get.media")) - gets,
        1,
        "no retry"
    );
    // beyond the end altogether: Drive says 416
    let r = s.env.read_partial(T::Pack, &id(0x40), 5000, 10);
    assert_eq!(r.class(), Some(EC::Internal), "{r:?}");
}

#[test]
fn quota_comes_from_about_and_counts_the_trash() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    rig.fake
        .with(|m| m.quota = (15_000_000_000, 9_000_000_000, 2_800_000_000));
    assert_eq!(
        s.env.quota(),
        Reply::Quota(pb::QuotaResult {
            limit: 15_000_000_000,
            usage: 9_000_000_000,
            usage_in_trash: 2_800_000_000
        })
    );
    rig.fake.with(|m| m.quota = (0, 5, 0));
    let Reply::Quota(q) = s.env.quota() else {
        panic!()
    };
    assert_eq!((q.limit, q.usage), (0, 5), "no limit reported means 0");
}

#[test]
fn a_cancelled_upload_is_answered_at_once_and_the_link_goes_on() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    let uploads_before = rig.fake.with(|m| m.count("upload"));
    let body = data(600_000, 1);
    let r = s.env.request(pb::repo_request::Op::Write(pb::Write {
        object_type: T::Pack as i32,
        id: bytes::Bytes::copy_from_slice(&id(0x21)),
        size: body.len() as u32,
    }));
    s.env.data_frame(r, &body[..200_000], false);
    s.env.cancel(r);
    assert_eq!(s.env.wait(r).class(), Some(EC::Cancelled));
    // the sender closes the aborted upload with END (it may be empty): the slot is then free
    s.env.data_frame(r, &[], true);
    assert_eq!(s.env.list(T::Pack), Reply::List(vec![]));
    assert_eq!(
        rig.fake.with(|m| m.count("upload")),
        uploads_before,
        "nothing was uploaded"
    );
    // a cancel for a request that is not outstanding is ignored
    s.env.cancel(999);
    s.env.ping(5);
    s.env.pump_for(Duration::from_millis(200));
    assert_eq!(s.env.pongs, [5]);
    assert_eq!(s.finish(), End::Bye);
}

#[test]
fn a_cancelled_request_in_a_hung_drive_call_is_answered_cancelled() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    s.env.write(T::Pack, &id(0x40), &data(1000, 5)).ok();
    rig.fake.with(|m| {
        m.inject(Fault {
            category: "get.media",
            skip: 0,
            times: 100,
            action: Action::Hang,
        })
    });
    let r = s.env.request(pb::repo_request::Op::ReadFull(pb::ReadFull {
        object_type: T::Pack as i32,
        id: bytes::Bytes::copy_from_slice(&id(0x40)),
    }));
    std::thread::sleep(Duration::from_millis(300));
    let began = Instant::now();
    s.env.cancel(r);
    assert_eq!(s.env.wait(r).class(), Some(EC::Cancelled));
    assert!(began.elapsed() < Duration::from_secs(3));
}

#[test]
fn a_download_that_has_begun_runs_to_its_end_whatever_is_cancelled() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    let body = data(3 * 1024 * 1024 + 17, 9);
    s.env.write(T::Pack, &id(0x40), &body).ok();
    let r = s.env.request(pb::repo_request::Op::ReadFull(pb::ReadFull {
        object_type: T::Pack as i32,
        id: bytes::Bytes::copy_from_slice(&id(0x40)),
    }));
    s.env.wait_read_begin(r);
    s.env.cancel(r);
    // no second answer: the stream just completes, intact
    assert_eq!(s.env.wait(r), Reply::Read(body));
    s.env.ping(1);
    s.env.pump_for(Duration::from_millis(100));
    assert_eq!(s.env.pongs, [1]);
}

#[test]
fn the_upload_rate_cap_limits_throughput_and_zero_lifts_it() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    let body = data(512 * 1024, 3);
    // warm the connection and the data folder so that only the pacing is measured
    s.env.write(T::Pack, &id(0x40), &body).ok();
    assert_eq!(s.env.set_rate(256 * 1024), Reply::Done);
    let began = Instant::now();
    s.env.write(T::Pack, &id(0x41), &body).ok();
    let slow = began.elapsed();
    // 512 KiB at 256 KiB/s with no initial burst: at least (512 - 64) / 256 = 1.75 s
    assert!(slow >= Duration::from_millis(1600), "{slow:?}");
    assert_eq!(s.env.set_rate(0), Reply::Done);
    let began = Instant::now();
    s.env.write(T::Pack, &id(0x42), &body).ok();
    assert!(
        began.elapsed() < slow / 2,
        "{:?} vs {slow:?}",
        began.elapsed()
    );
    rig.fake
        .with(|m| assert_eq!(m.get(&path_of(T::Pack, &id(0x42))).unwrap(), body));
}

#[test]
fn the_repository_tree_is_deleted_leaves_first_and_never_trashed() {
    use hx_backup_worker::drive::creds::Token;
    use hx_backup_worker::drive::gdrive::{Drive, OpenParams};
    use hx_backup_worker::drive::rate::UploadRate;
    use hx_backup_worker::drive::retry::{Cancel, Retrier};
    use hx_backup_worker::drive::transport::GoogleTransport;
    use std::sync::Arc;

    let rig = Rig::new();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let retrier = Arc::new(Retrier::new(rig.cfg.timing));
        let transport =
            GoogleTransport::new(&rig.cfg.http, Arc::new(UploadRate::new()), rig.cfg.timing)
                .unwrap();
        let token = Token::parse(token_json().as_bytes()).unwrap();
        let drive = Drive::new(retrier, transport, rig.cfg.client.clone(), token, b"host");
        let cancel = Cancel::never();
        let params = OpenParams {
            folder: "repo".into(),
            create: true,
            server_id: SERVER_A,
            takeover: false,
        };
        let repo = drive.open(&params, &cancel).await.unwrap();
        repo.create(&cancel).await.unwrap();
        for i in 0..3u8 {
            let body = vec![bytes::Bytes::from(data(1000, i))];
            repo.write(T::Pack, &id(0x10 + i * 0x40), body, &cancel)
                .await
                .unwrap();
            repo.write(
                T::Index,
                &id(i + 1),
                vec![bytes::Bytes::from_static(b"i")],
                &cancel,
            )
            .await
            .unwrap();
        }
        // the fake refuses to delete a folder that still has children, as Drive does
        repo.purge_tree(&cancel).await.unwrap();
    });
    rig.fake.with(|m| {
        assert_eq!(
            m.paths(),
            Vec::<String>::new(),
            "everything below My Drive is gone"
        );
        assert_eq!(m.trashed_count(), 0);
        assert_eq!(m.count("trash"), 0);
    });
}
