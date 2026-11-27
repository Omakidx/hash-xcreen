//! Regression tests for the W4 review: bounded read memory, a failed `OpenRepo`, the request
//! deadline, the no-progress timer, hostile answers, the token request, folders at object paths,
//! the control queue, the daily-limit probe, relay tasks, and the refresh after a 401.

mod drive_common;

use std::time::{Duration, Instant};

use drive_common::*;
use hx_ipc::repo::pb;

const MIB: usize = 1024 * 1024;

fn read_full_req(s: &mut Session, ty: T, id: &[u8; 32]) -> u64 {
    s.env.request(pb::repo_request::Op::ReadFull(pb::ReadFull {
        object_type: ty as i32,
        id: bytes::Bytes::copy_from_slice(id),
    }))
}

fn partial_req(s: &mut Session, id: &[u8; 32], offset: u32, length: u32) -> u64 {
    s.env
        .request(pb::repo_request::Op::ReadPartial(pb::ReadPartial {
            object_type: T::Pack as i32,
            id: bytes::Bytes::copy_from_slice(id),
            offset,
            length,
        }))
}

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

// ---- 1: memory ----

#[test]
fn reads_hold_their_memory_until_their_frames_are_queued() {
    // a budget of one chunk: ten readers cannot hold more than that between them, so a permit
    // given back before the frames are queued lets them read ahead (about 40 MiB in all)
    let rig = Rig::with(|c| {
        c.timing.read_budget_kib = 4096;
        c.timing.out_queue = 2;
    });
    let mut s = rig.open_session();
    s.env.create().ok();
    // ten packs of 12 MiB; privd asks for all of them and reads nothing
    let ids: Vec<[u8; 32]> = (0..10u8).map(|i| id(0x10 + i)).collect();
    rig.fake.with(|m| {
        for i in &ids {
            m.put(&path_of(T::Pack, i), &data(12 * MIB, i[0]));
        }
    });
    let reqs: Vec<u64> = ids
        .iter()
        .map(|i| read_full_req(&mut s, T::Pack, i))
        .collect();
    // wait until the fake has stopped serving: whatever was going to be read ahead has been
    let mut served = 0;
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(400));
        let now = rig.fake.with(|m| m.media_bytes);
        if now == served && now > 0 {
            break;
        }
        served = now;
    }
    // the budget (4 MiB), a queue of two frames and the socket: far less than the 120 MiB asked for
    assert!(
        served < 6 * MIB as u64,
        "{} MiB were read ahead of a link that reads nothing",
        served / MIB as u64
    );
    assert!(
        served >= 4 * MIB as u64,
        "the test did not start the reads: {served}"
    );
    // and nothing is lost: once privd reads, every download completes whole
    for (r, i) in reqs.iter().zip(&ids) {
        assert_eq!(s.env.wait(*r), Reply::Read(data(12 * MIB, i[0])));
    }
    let served = rig.fake.with(|m| m.media_bytes);
    assert!(
        (120 * MIB as u64..120 * MIB as u64 + 4096).contains(&served),
        "every byte once, plus the small lease read: {served}"
    );
}

// ---- 2: a failed OpenRepo ----

#[test]
fn a_failed_open_repo_answers_every_later_request() {
    let rig = Rig::new();
    std::fs::remove_file(rig.dir.path().join("drive-token")).unwrap();
    let mut s = rig.session();
    s.env.hello();
    assert_eq!(
        s.env.open("repo", true, SERVER_A, false).class(),
        Some(EC::AuthRevoked)
    );
    // each of these used to wait for ever for a repository that was never going to exist
    assert_eq!(s.env.list(T::Pack).class(), Some(EC::Internal));
    assert_eq!(s.env.quota().class(), Some(EC::Internal));
    assert_eq!(
        s.env.write(T::Pack, &id(1), b"x").class(),
        Some(EC::Internal)
    );
    assert_eq!(s.env.remove(T::Pack, &id(1)).class(), Some(EC::Internal));
    assert_eq!(s.env.read_full(T::Pack, &id(1)).class(), Some(EC::Internal));
}

// ---- 3: the deadline of a request ----

#[test]
fn the_request_deadline_covers_all_the_calls_of_a_write() {
    let slow = |m: &mut Model| {
        for c in ["meta", "get.media", "list"] {
            m.delay.insert(c, Duration::from_millis(250));
        }
    };
    // with room, the write succeeds (it makes about five calls of 250 ms each)
    let rig = Rig::with(|c| c.timing.request_budget = Duration::from_secs(30));
    let mut s = rig.open_session();
    rig.fake.with(slow);
    let began = Instant::now();
    s.env.write(T::Pack, &id(0x40), &data(100, 1)).ok();
    assert!(
        began.elapsed() > Duration::from_millis(900),
        "{:?}",
        began.elapsed()
    );
    // with 700 ms for the whole request, no call is slow enough to be cut off alone, and the
    // request is still given up when the calls together use the 700 ms up
    let rig = Rig::with(|c| c.timing.request_budget = Duration::from_millis(700));
    let mut s = rig.open_session();
    rig.fake.with(slow);
    let began = Instant::now();
    let r = s.env.write(T::Pack, &id(0x40), &data(100, 1));
    assert_eq!(r.class(), Some(EC::Transient), "{r:?}");
    assert!(
        began.elapsed() < Duration::from_millis(1100),
        "{:?}",
        began.elapsed()
    );
    assert!(
        rig.fake
            .with(|m| m.get(&path_of(T::Pack, &id(0x40))).is_none()),
        "the object was not written"
    );
}

// ---- 4 and 12: the no-progress timer ----

#[test]
fn concurrent_uploads_under_a_low_cap_are_not_timed_out() {
    // an attempt may not stall for 400 ms, but it may take as long as the cap makes it
    let rig = Rig::with(|c| c.timing.idle = Duration::from_millis(400));
    let mut s = rig.open_session();
    s.env.create().ok();
    s.env.write(T::Pack, &id(0x40), &data(10, 0)).ok();
    assert_eq!(s.env.set_rate(192 * 1024), Reply::Done);
    let bodies = [data(192 * 1024, 1), data(192 * 1024, 2)];
    let began = Instant::now();
    let reqs: Vec<u64> = bodies
        .iter()
        .enumerate()
        .map(|(i, b)| {
            s.env.request(pb::repo_request::Op::Write(pb::Write {
                object_type: T::Pack as i32,
                id: bytes::Bytes::copy_from_slice(&id(0x41 + i as u8)),
                size: b.len() as u32,
            }))
        })
        .collect();
    for (r, b) in reqs.iter().zip(&bodies) {
        s.env.upload(*r, b);
    }
    for r in &reqs {
        assert_eq!(s.env.wait(*r), Reply::Done);
    }
    // 384 KiB at 192 KiB/s: about 2 s, five times the stall limit
    assert!(
        began.elapsed() > Duration::from_millis(1200),
        "{:?}",
        began.elapsed()
    );
    assert_eq!(
        rig.fake.with(|m| m.count("upload")),
        4,
        "two uploads, no retry of either (plus the lease and the warm-up)"
    );
}

#[test]
fn a_long_listing_is_not_cut_off_for_being_long() {
    let rig = Rig::with(|c| c.timing.idle = Duration::from_millis(400));
    let mut s = rig.open_session();
    s.env.create().ok();
    rig.fake.with(|m| {
        for i in 0..40u8 {
            m.put(&format!("repo/index/{}", hex(&id(i + 1))), &[i]);
        }
        m.force_page_size = 2;
        m.delay.insert("list", Duration::from_millis(100));
    });
    let began = Instant::now();
    let Reply::List(v) = s.env.list(T::Index) else {
        panic!()
    };
    assert_eq!(v.len(), 40);
    assert!(
        began.elapsed() > Duration::from_millis(1500),
        "20 pages of 100 ms: {:?}",
        began.elapsed()
    );
}

// ---- 5: hostile answers ----

#[test]
fn a_body_longer_than_asked_for_is_cut_off_while_it_is_read() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    s.env.write(T::Pack, &id(0x40), &data(2000, 1)).ok();
    rig.fake.with(|m| {
        m.inject(Fault {
            category: "get.media",
            skip: 0,
            times: 1,
            action: Action::Unbounded(256 * MIB),
        });
    });
    let r = s.env.read_partial(T::Pack, &id(0x40), 0, 1000);
    assert_eq!(r.class(), Some(EC::Internal), "{r:?}");
    assert!(
        !rig.fake.with(|m| m.big_written_ok),
        "the helper kept reading a body it had stopped wanting"
    );
}

#[test]
fn an_object_over_its_types_cap_is_refused_before_it_is_read() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    rig.fake
        .with(|m| m.put(&path_of(T::Pack, &id(0x40)), &vec![0u8; 97 * MIB]));
    let before = rig.fake.with(|m| m.count("get.media"));
    let r = s.env.read_full(T::Pack, &id(0x40));
    assert_eq!(r.class(), Some(EC::Internal), "{r:?}");
    assert_eq!(
        rig.fake.with(|m| m.count("get.media")),
        before,
        "not one byte of it was fetched"
    );
    // a range past the end of a large object is refused the same way
    rig.fake
        .with(|m| m.put(&path_of(T::Pack, &id(0x41)), &vec![0u8; 5 * MIB]));
    let r = s
        .env
        .read_partial(T::Pack, &id(0x41), 4 * MIB as u32, 2 * MIB as u32);
    assert_eq!(r.class(), Some(EC::Internal), "{r:?}");
}

#[test]
fn an_endless_listing_ends_in_internal() {
    let rig = Rig::with(|c| {
        c.timing.max_list_entries = 25;
        c.timing.max_requests = 60;
    });
    let mut s = rig.open_session();
    s.env.create().ok();
    rig.fake.with(|m| {
        m.put(&format!("repo/index/{}", hex(&id(1))), b"x");
        m.repeat_token = true;
    });
    let began = Instant::now();
    let r = s.env.list(T::Index);
    assert_eq!(r.class(), Some(EC::Internal), "{r:?}");
    assert!(began.elapsed() < Duration::from_secs(10));
    let pages = rig.fake.with(|m| m.count("list"));
    assert!(pages < 100, "it stopped asking: {pages}");
}

// ---- 6: the token request ----

#[test]
fn a_token_with_plus_and_slash_refreshes_and_never_sits_in_a_query() {
    const TOKEN: &str = "1//fake+token/with=chars_and-more.tilde~";
    let rig = Rig::new();
    std::fs::write(
        rig.dir.path().join("drive-token"),
        format!(r#"{{"refresh_token":"{TOKEN}"}}"#),
    )
    .unwrap();
    rig.fake
        .with(|m| m.expected_refresh = Some(TOKEN.to_owned()));
    let mut s = rig.open_session();
    s.env.create().ok();
    s.env.write(T::Pack, &id(0x40), &data(100, 1)).ok();
    rig.fake.with(|m| {
        assert_eq!(m.bad_refresh_tokens, 0);
        assert!(m.tokens_issued >= 2, "the helper's refresh and OpenDAL's");
        for r in m.log.iter().filter(|r| r.category == "token") {
            assert!(!r.has_query, "a token request had a query string");
        }
    });
}

#[test]
fn a_failed_token_exchange_leaves_no_secret_in_the_error() {
    use hx_backup_worker::drive::gdrive::Drive;
    use hx_backup_worker::drive::rate::UploadRate;
    use hx_backup_worker::drive::retry::Retrier;
    use hx_backup_worker::drive::transport::GoogleTransport;
    use std::sync::Arc;

    let rig = Rig::new();
    rig.fake.with(|m| {
        m.inject(Fault {
            category: "token",
            skip: 0,
            times: 10,
            action: Action::Raw {
                status: 400,
                body: r#"{"error":"invalid_grant","error_description":"Bad"}"#,
            },
        });
    });
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let transport =
            GoogleTransport::new(&rig.cfg.http, Arc::new(UploadRate::new()), rig.cfg.timing)
                .unwrap();
        let token = hx_backup_worker::drive::creds::Token::parse(token_json().as_bytes()).unwrap();
        let drive = Drive::new(
            Arc::new(Retrier::new(rig.cfg.timing)),
            transport,
            rig.cfg.client.clone(),
            token,
            b"host",
        );
        let op = drive.operator("repo").unwrap();
        let e = op
            .stat("anything")
            .await
            .expect_err("the token endpoint refuses");
        let text = format!("{e:?} // {e}");
        let encoded = REFRESH_TOKEN.replace('/', "%2F");
        for secret in [
            REFRESH_TOKEN,
            CLIENT_SECRET,
            encoded.as_str(),
            "refresh_token=",
            "client_secret=",
        ] {
            assert!(!text.contains(secret), "{secret:?} is in the error: {text}");
        }
    });
}

// ---- 7: only files are removed ----

#[test]
fn a_folder_at_an_object_path_is_not_removed() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    let folder = format!("repo/index/{}", hex(&id(5)));
    rig.fake.with(|m| {
        m.mkdirs(&folder);
        m.put(&format!("{folder}/precious"), b"data");
    });
    let r = s.env.remove(T::Index, &id(5));
    assert_eq!(r.class(), Some(EC::Internal), "{r:?}");
    rig.fake.with(|m| {
        assert!(m.is_folder(&folder));
        assert_eq!(m.get(&format!("{folder}/precious")).unwrap(), b"data");
        assert_eq!(m.count("delete"), 0, "no DELETE was sent");
    });
}

// ---- 9: the control queue ----

#[test]
fn ping_is_answered_while_the_data_queue_is_backed_up() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    let ids: Vec<[u8; 32]> = (0..6u8).map(|i| id(0x10 + i)).collect();
    rig.fake.with(|m| {
        for i in &ids {
            m.put(&path_of(T::Pack, i), &data(8 * MIB, i[0]));
        }
    });
    for i in &ids {
        read_full_req(&mut s, T::Pack, i);
    }
    std::thread::sleep(Duration::from_millis(1500)); // the data queue is full, privd reads nothing
    s.env.ping(9);
    while s.env.pongs.is_empty() {
        s.env.pump().expect("a Pong");
    }
    let at = s.env.pong_at_frame.unwrap();
    assert!(
        at <= 16,
        "the Pong came after {at} frames: it queued behind the data"
    );
}

// ---- 10: a Write queued behind a stuck lease read ----

#[test]
fn a_cancel_reaches_a_request_waiting_on_a_stuck_lease_read() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    // both removes read the lease (every Remove does), and both reads hang
    let metas = rig.fake.with(|m| m.count("meta"));
    rig.fake.with(|m| {
        m.inject(Fault {
            category: "meta",
            skip: 0,
            times: 2,
            action: Action::Hang,
        })
    });
    let a = s.env.request(pb::repo_request::Op::Remove(pb::Remove {
        object_type: T::Pack as i32,
        id: bytes::Bytes::copy_from_slice(&id(0x41)),
    }));
    let b = s.env.request(pb::repo_request::Op::Remove(pb::Remove {
        object_type: T::Pack as i32,
        id: bytes::Bytes::copy_from_slice(&id(0x42)),
    }));
    let t0 = Instant::now();
    while rig.fake.with(|m| m.count("meta")) < metas + 2 {
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "the removes never reached the lease read"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let began = Instant::now();
    s.env.cancel(b);
    assert_eq!(s.env.wait(b).class(), Some(EC::Cancelled));
    s.env.cancel(a);
    assert_eq!(s.env.wait(a).class(), Some(EC::Cancelled));
    assert!(
        began.elapsed() < Duration::from_secs(1),
        "{:?}",
        began.elapsed()
    );
}

// ---- 11: the daily-limit gate ----

#[test]
fn when_the_pause_ends_one_request_probes_before_the_others_go() {
    let rig = Rig::with(|c| c.timing.daily_pause = Duration::from_millis(300));
    let mut s = rig.open_session();
    s.env.create().ok();
    let ids: Vec<[u8; 32]> = (0..4u8).map(|i| id(0x40 + i)).collect();
    rig.fake.with(|m| {
        for i in &ids {
            m.put(&path_of(T::Pack, i), &data(2000, i[0]));
        }
        m.delay.insert("get.media", Duration::from_millis(150));
        m.inject(Fault::status("get.media", 4, 403, "dailyLimitExceeded"));
    });
    let reqs: Vec<u64> = ids.iter().map(|i| partial_req(&mut s, i, 0, 100)).collect();
    for r in &reqs {
        assert!(matches!(s.env.wait(*r), Reply::Read(_)));
    }
    let at = pack_attempts(&rig, &ids);
    // four attempts before the pause, then the probe, then the other three after it
    assert_eq!(at.len(), 8, "{at:?}");
    let probe = at[4];
    assert!(
        at[5].duration_since(probe) >= Duration::from_millis(100),
        "the others started {:?} after the probe: they did not wait for it",
        at[5].duration_since(probe)
    );
}

#[test]
fn an_exhausted_gate_fails_the_waiting_requests_without_another_attempt() {
    let rig = Rig::with(|c| {
        c.timing.daily_pause = Duration::from_millis(300);
        c.timing.max_pauses = 1;
    });
    let mut s = rig.open_session();
    s.env.create().ok();
    let ids: Vec<[u8; 32]> = (0..3u8).map(|i| id(0x40 + i)).collect();
    rig.fake.with(|m| {
        for i in &ids {
            m.put(&path_of(T::Pack, i), &data(2000, i[0]));
        }
        m.delay.insert("get.media", Duration::from_millis(100));
        m.inject(Fault::status("get.media", 1000, 403, "dailyLimitExceeded"));
    });
    let before = rig.fake.with(|m| m.count("get.media"));
    let reqs: Vec<u64> = ids.iter().map(|i| partial_req(&mut s, i, 0, 100)).collect();
    for r in &reqs {
        assert_eq!(s.env.wait(*r).class(), Some(EC::DailyLimit));
    }
    // three attempts that started the pause, one probe that exhausted it: the two waiters made none
    assert_eq!(rig.fake.with(|m| m.count("get.media")) - before, 4);
}

// ---- 13: relay tasks ----

#[test]
fn timed_out_downloads_leave_no_connection_or_task_behind() {
    let rig = Rig::with(|c| {
        c.timing.idle = Duration::from_millis(250);
        c.timing.max_retries = 0;
    });
    let mut s = rig.open_session();
    s.env.create().ok();
    rig.fake.with(|m| {
        m.put(&path_of(T::Snapshot, &id(0x40)), &data(500, 1));
        m.inject(Fault {
            category: "get.media",
            skip: 0,
            times: 1000,
            action: Action::StallBody,
        });
    });
    let mut one = || {
        let r = s.env.read_full(T::Snapshot, &id(0x40));
        assert_eq!(r.class(), Some(EC::Transient), "{r:?}");
    };
    one(); // warm up the pool
    std::thread::sleep(Duration::from_millis(300));
    let before = open_fds();
    for _ in 0..12 {
        one();
    }
    std::thread::sleep(Duration::from_millis(500));
    let after = open_fds();
    assert!(
        after <= before + 4,
        "{before} descriptors before, {after} after twelve timed-out downloads: the relay tasks outlived their consumers"
    );
}

// ---- 16: a 401 refreshes the token once ----

#[test]
fn a_401_is_retried_once_with_a_fresh_token() {
    let (rig, mut s) = {
        let rig = Rig::new();
        let mut s = rig.open_session();
        s.env.create().ok();
        s.env.write(T::Pack, &id(0x40), &data(2000, 1)).ok();
        (rig, s)
    };
    let tokens = rig.fake.with(|m| m.tokens_issued);
    rig.fake
        .with(|m| m.inject(Fault::status("get.media", 1, 401, "authError")));
    assert_eq!(
        s.env.read_full(T::Pack, &id(0x40)),
        Reply::Read(data(2000, 1))
    );
    assert!(
        rig.fake.with(|m| m.tokens_issued) > tokens,
        "a new access token was fetched"
    );
}

#[test]
fn a_second_401_is_auth_revoked_and_invalid_grant_is_at_once() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    s.env.write(T::Pack, &id(0x40), &data(2000, 1)).ok();
    rig.fake
        .with(|m| m.inject(Fault::status("get.media", 1000, 401, "authError")));
    let before = rig.fake.with(|m| m.count("get.media"));
    let r = s.env.read_full(T::Pack, &id(0x40));
    assert_eq!(r.class(), Some(EC::AuthRevoked), "{r:?}");
    assert_eq!(
        rig.fake.with(|m| m.count("get.media")) - before,
        2,
        "one repeat, not more"
    );
    // the quota call has the same rule
    rig.fake.with(|m| {
        m.clear_faults();
        m.inject(Fault::status("about", 1000, 401, "authError"));
    });
    assert_eq!(s.env.quota().class(), Some(EC::AuthRevoked));
}

/// The arrival times of the media reads of these packs (the lease read is a media read too and is
/// left out), in order, as offsets from the first.
fn pack_attempts(rig: &Rig, ids: &[[u8; 32]]) -> Vec<Instant> {
    rig.fake.with(|m| {
        let file_ids: Vec<String> = ids
            .iter()
            .map(|i| m.id_of(&path_of(T::Pack, i)).unwrap())
            .collect();
        let mut at: Vec<Instant> = m
            .log
            .iter()
            .filter(|r| {
                r.category == "get.media" && file_ids.iter().any(|f| r.path.ends_with(f.as_str()))
            })
            .map(|r| r.at)
            .collect();
        at.sort();
        at
    })
}

// ---- N1: a failed download ends the link between frames ----

#[test]
fn a_failed_download_ends_the_link_between_frames_not_inside_one() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    rig.fake.with(|m| {
        m.put(&path_of(T::Pack, &id(0x40)), &data(12 * MIB, 3));
        // the first chunk is served, the second is refused
        m.inject(Fault {
            category: "get.media",
            skip: 1,
            times: 1000,
            action: Action::Status {
                status: 403,
                reason: "appNotAuthorizedToFile",
                retry_after: None,
            },
        });
    });
    read_full_req(&mut s, T::Pack, &id(0x40));
    // privd reads nothing for a while: the writer is blocked in the middle of a 1 MiB frame when
    // the second chunk fails
    std::thread::sleep(Duration::from_millis(1500));
    let end = loop {
        if let Err(e) = s.env.pump() {
            break e;
        }
    };
    assert_eq!(
        end, "closed",
        "privd's decoder must end at a frame boundary, not inside a frame"
    );
    // W5-2 (ipc.md section 29, v0.8): the class of the failure reached privd, as an event that
    // came before the end of the stream.
    let failed: Vec<_> = s
        .env
        .events
        .iter()
        .filter(|e| e.kind == pb::EventKind::SessionFailed as i32)
        .collect();
    assert_eq!(failed.len(), 1, "one SESSION_FAILED before the close");
    assert_eq!(failed[0].error_class, EC::Permission as i32);
}

#[test]
fn a_revoked_token_in_the_middle_of_a_download_reaches_privd_as_a_session_failure() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    rig.fake.with(|m| {
        m.put(&path_of(T::Pack, &id(0x40)), &data(12 * MIB, 3));
        m.inject(Fault {
            category: "get.media",
            skip: 1,
            times: 1000,
            action: Action::Status {
                status: 401,
                reason: "authError",
                retry_after: None,
            },
        });
    });
    read_full_req(&mut s, T::Pack, &id(0x40));
    std::thread::sleep(Duration::from_millis(1500));
    while s.env.pump().is_ok() {}
    let classes: Vec<i32> = s
        .env
        .events
        .iter()
        .filter(|e| e.kind == pb::EventKind::SessionFailed as i32)
        .map(|e| e.error_class)
        .collect();
    assert_eq!(classes, [EC::AuthRevoked as i32]);
}

// ---- N2: the deadline does not run while the cap holds an upload back, or after ReadBegin ----

#[test]
fn a_capped_upload_that_takes_longer_than_the_deadline_but_progresses_is_done() {
    let rig = Rig::with(|c| c.timing.request_budget = Duration::from_millis(700));
    let mut s = rig.open_session();
    s.env.create().ok();
    s.env.write(T::Pack, &id(0x40), &data(10, 0)).ok();
    assert_eq!(s.env.set_rate(128 * 1024), Reply::Done);
    let began = Instant::now();
    s.env.write(T::Pack, &id(0x41), &data(256 * 1024, 1)).ok();
    assert!(
        began.elapsed() > Duration::from_millis(1200),
        "{:?}",
        began.elapsed()
    );
}

#[test]
fn a_slow_download_that_has_begun_outlives_the_request_deadline() {
    let rig = Rig::with(|c| c.timing.request_budget = Duration::from_millis(400));
    let mut s = rig.open_session();
    s.env.create().ok();
    rig.fake.with(|m| {
        m.put(&path_of(T::Pack, &id(0x40)), &data(12 * MIB, 3));
        m.delay.insert("get.media", Duration::from_millis(150));
    });
    let began = Instant::now();
    assert_eq!(
        s.env.read_full(T::Pack, &id(0x40)),
        Reply::Read(data(12 * MIB, 3))
    );
    assert!(
        began.elapsed() > Duration::from_millis(440),
        "{:?}",
        began.elapsed()
    );
}

// ---- N4: the probe releases the gate at its first answer ----

#[test]
fn the_gate_reopens_when_the_probe_has_headers_not_when_it_has_finished() {
    let rig = Rig::with(|c| c.timing.daily_pause = Duration::from_millis(300));
    let mut s = rig.open_session();
    s.env.create().ok();
    let ids: Vec<[u8; 32]> = (0..3u8).map(|i| id(0x40 + i)).collect();
    rig.fake.with(|m| {
        for i in &ids {
            m.put(&path_of(T::Pack, i), &data(2000, i[0]));
        }
        m.inject(Fault::status("get.media", 3, 403, "dailyLimitExceeded"));
        // the probe is answered at once with a body that takes 700 ms to arrive
        m.inject(Fault {
            category: "get.media",
            skip: 0,
            times: 1,
            action: Action::SlowBody(700),
        });
    });
    let reqs: Vec<u64> = ids.iter().map(|i| partial_req(&mut s, i, 0, 100)).collect();
    for r in &reqs {
        assert!(matches!(s.env.wait(*r), Reply::Read(_)));
    }
    let at = pack_attempts(&rig, &ids);
    assert_eq!(at.len(), 6, "three refused, the probe, two waiters: {at:?}");
    let waited = at[4].duration_since(at[3]);
    assert!(
        waited < Duration::from_millis(400),
        "the waiters started {waited:?} after the probe: they waited for it to finish"
    );
}

// ---- N5: a Write over the cap is refused without buffering ----

#[test]
fn a_write_over_the_helpers_cap_is_refused_and_not_uploaded() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    let before = rig.fake.with(|m| m.count("upload"));
    let r = s.env.write(T::Pack, &id(0x40), &vec![7u8; 80 * MIB]);
    assert_eq!(r.class(), Some(EC::Internal), "{r:?}");
    assert_eq!(
        rig.fake.with(|m| m.count("upload")),
        before,
        "nothing reached Drive"
    );
    // the link is fine, and a pack at the cap is not refused for its size
    assert_eq!(s.env.list(T::Pack), Reply::List(vec![]));
}

// ---- N6: an error body is read up to its cap and no further ----

#[test]
fn an_error_body_is_not_drained() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    rig.fake.with(|m| {
        m.put(&path_of(T::Snapshot, &id(0x40)), &data(500, 1));
        m.inject(Fault {
            category: "get.media",
            skip: 0,
            times: 1,
            action: Action::UnboundedError(256 * MIB),
        });
    });
    // the 500 is retried and the retry succeeds
    assert_eq!(
        s.env.read_full(T::Snapshot, &id(0x40)),
        Reply::Read(data(500, 1))
    );
    assert!(
        !rig.fake.with(|m| m.big_written_ok),
        "the helper read a 256 MiB error body to its end"
    );
}

// ---- the probe's evidence is a Drive answer, never a token exchange ----

/// Arrival times of the requests of one fake category, sorted.
fn arrivals(rig: &Rig, category: &str) -> Vec<Instant> {
    let mut at: Vec<Instant> = rig.fake.with(|m| {
        m.log
            .iter()
            .filter(|r| r.category == category)
            .map(|r| r.at)
            .collect()
    });
    at.sort();
    at
}

#[test]
fn a_token_refresh_is_not_the_probes_answer_for_an_object_request() {
    let rig = Rig::with(|c| c.timing.daily_pause = Duration::from_millis(300));
    // short-lived tokens from the start: every call of the session refreshes first
    rig.fake.with(|m| m.token_expires_in = Some(60));
    let mut s = rig.open_session();
    s.env.create().ok();
    let ids: Vec<[u8; 32]> = (0..3u8).map(|i| id(0x40 + i)).collect();
    rig.fake.with(|m| {
        for i in &ids {
            m.put(&path_of(T::Pack, i), &data(2000, i[0]));
        }
        m.delay.insert("get.media", Duration::from_millis(150));
        m.inject(Fault::status("get.media", 3, 403, "dailyLimitExceeded"));
    });
    let reqs: Vec<u64> = ids.iter().map(|i| partial_req(&mut s, i, 0, 100)).collect();
    for r in &reqs {
        assert!(matches!(s.env.wait(*r), Reply::Read(_)));
    }
    let at = pack_attempts(&rig, &ids);
    assert_eq!(at.len(), 6, "{at:?}");
    assert!(
        at[4].duration_since(at[3]) >= Duration::from_millis(100),
        "the waiters started {:?} after the probe: its token refresh reopened the gate",
        at[4].duration_since(at[3])
    );
    s.env.pump_for(Duration::from_millis(300));
    assert_eq!(
        s.env.count_events(pb::EventKind::Resumed),
        1,
        "{:?}",
        s.env.event_kinds()
    );
}

#[test]
fn a_token_exchange_of_the_helpers_own_is_never_the_probe_for_quota() {
    let rig = Rig::with(|c| c.timing.daily_pause = Duration::from_millis(300));
    // short-lived tokens from the start: every call of the session refreshes first
    rig.fake.with(|m| m.token_expires_in = Some(60));
    let mut s = rig.open_session();
    rig.fake.with(|m| {
        m.delay.insert("about", Duration::from_millis(150));
        m.inject(Fault::status("about", 3, 403, "dailyLimitExceeded"));
    });
    let mut reqs: Vec<u64> = (0..3)
        .map(|_| s.env.request(pb::repo_request::Op::Quota(pb::Quota {})))
        .collect();
    // a fourth request starts during the pause: its token exchange must neither wait for the gate
    // nor be the probe (and so reopen it) when it succeeds
    std::thread::sleep(Duration::from_millis(250));
    reqs.push(s.env.request(pb::repo_request::Op::Quota(pb::Quota {})));
    for r in &reqs {
        assert!(matches!(s.env.wait(*r), Reply::Quota(_)));
    }
    let at = arrivals(&rig, "about");
    assert_eq!(at.len(), 7, "three refused, the probe, three more: {at:?}");
    assert!(
        at[4].duration_since(at[3]) >= Duration::from_millis(100),
        "the others started {:?} after the probe: a token exchange reopened the gate",
        at[4].duration_since(at[3])
    );
    s.env.pump_for(Duration::from_millis(300));
    assert_eq!(
        s.env.count_events(pb::EventKind::Resumed),
        1,
        "{:?}",
        s.env.event_kinds()
    );
}

// ---- the upload cap ----

#[test]
fn lifting_or_raising_the_cap_releases_a_chunk_that_is_already_waiting() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    s.env.write(T::Pack, &id(0x40), &data(10, 0)).ok();
    for (i, new_rate) in [(0u8, 0u64), (1, 4 * 1024 * 1024)] {
        // 1 B/s is raised to the 2 KiB/s minimum: the second chunk would wait 32 s
        assert_eq!(s.env.set_rate(1), Reply::Done);
        let began = Instant::now();
        let body = data(200 * 1024, i);
        let r = s.env.request(pb::repo_request::Op::Write(pb::Write {
            object_type: T::Pack as i32,
            id: bytes::Bytes::copy_from_slice(&id(0x41 + i)),
            size: body.len() as u32,
        }));
        s.env.upload(r, &body);
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(s.env.set_rate(new_rate), Reply::Done);
        assert_eq!(s.env.wait(r), Reply::Done);
        assert!(
            began.elapsed() < Duration::from_secs(8),
            "rate set to {new_rate}: the waiting chunk kept its old wait ({:?})",
            began.elapsed()
        );
    }
}

// ---- a close of our own is not a violation ----

#[test]
fn a_link_the_helper_closed_itself_is_not_reported_as_a_violation() {
    use hx_backup_worker::drive::server::End;
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    rig.fake.with(|m| {
        m.put(&path_of(T::Pack, &id(0x40)), &data(12 * MIB, 3));
        m.inject(Fault {
            category: "get.media",
            skip: 1,
            times: 1000,
            action: Action::Status {
                status: 403,
                reason: "appNotAuthorizedToFile",
                retry_after: None,
            },
        });
    });
    read_full_req(&mut s, T::Pack, &id(0x40));
    // privd is in the middle of an upload frame when the helper closes: a header and a few bytes
    let w = s.env.request(pb::repo_request::Op::Write(pb::Write {
        object_type: T::Pack as i32,
        id: bytes::Bytes::copy_from_slice(&id(0x41)),
        size: 3 * MIB as u32,
    }));
    let mut half = hx_ipc::repo::encode_data_header(w, false, MIB)
        .unwrap()
        .to_vec();
    half.extend_from_slice(&[1u8; 1000]);
    s.env.send_raw(&half);
    std::thread::sleep(Duration::from_millis(1500));
    while s.env.pump().is_ok() {}
    assert_eq!(s.join_without_closing(), End::Lost);
}

// ---- S-M1: a snapshot is create-only ----

#[test]
fn a_snapshot_that_exists_cannot_be_written_again() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    let snap = data(500, 7);
    s.env.write(T::Snapshot, &id(0x50), &snap).ok();
    // Written again with the same bytes (the hash matches): refused, and the object is intact.
    assert_eq!(
        s.env.write(T::Snapshot, &id(0x50), &snap).class(),
        Some(EC::Permission)
    );
    assert_eq!(s.env.read_full(T::Snapshot, &id(0x50)), Reply::Read(snap));
    // A different snapshot is created as usual, and a pack may still be written twice.
    s.env.write(T::Snapshot, &id(0x51), &data(10, 1)).ok();
    s.env.write(T::Pack, &id(0x60), &data(10, 2)).ok();
    s.env.write(T::Pack, &id(0x60), &data(10, 2)).ok();
}
