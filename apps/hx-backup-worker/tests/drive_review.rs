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
    let rig = Rig::new();
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
    std::thread::sleep(Duration::from_millis(2000));
    let served = rig.fake.with(|m| m.media_bytes);
    // the budget (32 MiB), the queue (16 MiB) and the socket: far less than the 120 MiB asked for
    assert!(
        served < 64 * MIB as u64,
        "{} MiB were read ahead of a link that reads nothing",
        served / MIB as u64
    );
    assert!(
        served >= 8 * MIB as u64,
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
    let mut at: Vec<Instant> = rig.fake.with(|m| {
        m.log
            .iter()
            .filter(|r| r.category == "get.media")
            .map(|r| r.at)
            .collect()
    });
    at.sort();
    // four attempts before the pause, then the probe, then the other three after it
    assert!(at.len() >= 8, "{}", at.len());
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
