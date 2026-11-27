//! Failures of Google, as the Drive helper maps them (ipc.md §31): every error class, the retries
//! and their counts, `Retry-After`, the shared daily-limit gate, the token, and the host
//! restriction. Faults are injected by the fake Google; nothing here touches a real network.

mod drive_common;

use std::time::{Duration, Instant};

use drive_common::*;
use hx_ipc::repo::pb;

/// A session with an object in place and `faults` injected for what follows.
fn case(faults: Vec<Fault>) -> (Rig, Session) {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    s.env.write(T::Pack, &id(0x40), &data(2000, 1)).ok();
    rig.fake.with(|m| {
        for f in faults {
            m.inject(f);
        }
    });
    (rig, s)
}

fn pack_read(s: &mut Session) -> Reply {
    s.env.read_full(T::Pack, &id(0x40))
}

fn list_index(s: &mut Session) -> Reply {
    s.env.list(T::Index)
}

macro_rules! class_case {
    ($name:ident, $fault:expr, $op:ident, $class:expr) => {
        #[test]
        fn $name() {
            let (_rig, mut s) = case(vec![$fault]);
            let r = $op(&mut s);
            assert_eq!(r.class(), Some($class), "{r:?}");
        }
    };
}

class_case!(
    http_429_is_rate_limited,
    Fault::status("list", 1000, 429, ""),
    list_index,
    EC::RateLimited
);
class_case!(
    rate_limit_exceeded_is_rate_limited,
    Fault::status("list", 1000, 403, "rateLimitExceeded"),
    list_index,
    EC::RateLimited
);
class_case!(
    user_rate_limit_exceeded_is_rate_limited,
    Fault::status("list", 1000, 403, "userRateLimitExceeded"),
    list_index,
    EC::RateLimited
);
class_case!(
    http_500_is_transient,
    Fault::status("list", 1000, 500, "backendError"),
    list_index,
    EC::Transient
);
class_case!(
    http_503_is_transient,
    Fault::status("get.media", 1000, 503, "backendError"),
    pack_read,
    EC::Transient
);
class_case!(
    http_408_is_transient,
    Fault::status("list", 1000, 408, ""),
    list_index,
    EC::Transient
);
class_case!(
    http_405_is_transient,
    Fault::status("list", 1000, 405, ""),
    list_index,
    EC::Transient
);
class_case!(
    a_dropped_connection_is_transient,
    Fault {
        category: "list",
        skip: 0,
        times: 1000,
        action: Action::Drop
    },
    list_index,
    EC::Transient
);
class_case!(
    a_truncated_download_is_transient,
    Fault {
        category: "get.media",
        skip: 0,
        times: 1000,
        action: Action::TruncateBody
    },
    pack_read,
    EC::Transient
);
class_case!(
    other_403_is_permission,
    Fault::status("list", 1000, 403, "appNotAuthorizedToFile"),
    list_index,
    EC::Permission
);
class_case!(
    a_403_without_a_reason_is_permission,
    Fault::status("list", 1000, 403, ""),
    list_index,
    EC::Permission
);
class_case!(
    http_401_is_auth_revoked,
    Fault::status("list", 1000, 401, "authError"),
    list_index,
    EC::AuthRevoked
);
class_case!(
    http_404_on_a_download_is_not_found,
    Fault::status("get.media", 1000, 404, "notFound"),
    pack_read,
    EC::NotFound
);

#[test]
fn storage_quota_is_not_retried() {
    let (rig, mut s) = case(vec![Fault::status(
        "upload",
        1000,
        403,
        "storageQuotaExceeded",
    )]);
    let before = rig.fake.with(|m| m.count("upload"));
    let r = s.env.write(T::Pack, &id(0x41), &data(1000, 2));
    assert_eq!(r.class(), Some(EC::QuotaExceeded), "{r:?}");
    assert_eq!(
        rig.fake.with(|m| m.count("upload")) - before,
        1,
        "one attempt"
    );
}

#[test]
fn fatal_classes_make_one_attempt() {
    for (status, reason, class) in [
        (401u16, "authError", EC::AuthRevoked),
        (403, "appNotAuthorizedToFile", EC::Permission),
    ] {
        let (rig, mut s) = case(vec![Fault::status("get.media", 1000, status, reason)]);
        let before = rig.fake.with(|m| m.count("get.media"));
        let r = pack_read(&mut s);
        assert_eq!(r.class(), Some(class));
        assert_eq!(
            rig.fake.with(|m| m.count("get.media")) - before,
            1,
            "{status}: one attempt"
        );
    }
}

#[test]
fn a_request_is_retried_eight_times_and_the_error_keeps_its_class() {
    let (rig, mut s) = case(vec![Fault::status("get.media", 1000, 503, "backendError")]);
    let before = rig.fake.with(|m| m.count("get.media"));
    let r = pack_read(&mut s);
    assert_eq!(r.class(), Some(EC::Transient));
    assert_eq!(
        rig.fake.with(|m| m.count("get.media")) - before,
        9,
        "one attempt and eight retries"
    );
    s.env.pump_for(Duration::from_millis(200));
    assert!(
        s.env.count_events(pb::EventKind::Retrying) >= 8,
        "{:?}",
        s.env.event_kinds()
    );
}

#[test]
fn a_transient_fault_that_clears_is_retried_to_success_after_the_backoff() {
    let (rig, mut s) = case(vec![Fault::status("upload", 3, 503, "backendError")]);
    let before = rig.fake.with(|m| m.count("upload"));
    let began = Instant::now();
    s.env.write(T::Pack, &id(0x41), &data(5000, 2)).ok();
    // the delays are 10, 20 and 40 ms with equal jitter: at least half of each
    assert!(
        began.elapsed() >= Duration::from_millis(35),
        "{:?}",
        began.elapsed()
    );
    assert_eq!(
        rig.fake.with(|m| m.count("upload")) - before,
        4,
        "three failures and the success"
    );
    assert_eq!(
        rig.fake
            .with(|m| m.get(&path_of(T::Pack, &id(0x41))).unwrap()),
        data(5000, 2)
    );
}

#[test]
fn retry_after_is_honoured() {
    let (_rig, mut s) = case(vec![Fault {
        category: "list",
        skip: 0,
        times: 1,
        action: Action::Status {
            status: 429,
            reason: "",
            retry_after: Some(1),
        },
    }]);
    let began = Instant::now();
    s.env.list(T::Index).ok();
    assert!(
        began.elapsed() >= Duration::from_secs(1),
        "{:?}",
        began.elapsed()
    );
}

#[test]
fn a_rate_limited_answer_carries_the_last_retry_after() {
    let rig = Rig::with(|c| c.timing.max_retries = 1);
    let mut s = rig.open_session();
    rig.fake.with(|m| {
        m.inject(Fault {
            category: "list",
            skip: 0,
            times: 1000,
            action: Action::Status {
                status: 429,
                reason: "",
                retry_after: Some(1),
            },
        });
    });
    let r = s.env.list(T::Index);
    assert_eq!(
        r,
        Reply::Error(EC::RateLimited, 1000),
        "the hint is Drive's"
    );
}

#[test]
fn a_hung_drive_call_times_out_and_is_retried_then_transient() {
    let rig = Rig::with(|c| {
        c.timing.attempt_base = Duration::from_millis(300);
        c.timing.max_retries = 2;
    });
    let mut s = rig.open_session();
    s.env.create().ok();
    s.env.write(T::Pack, &id(0x40), &data(2000, 1)).ok();
    rig.fake.with(|m| {
        m.inject(Fault {
            category: "get.media",
            skip: 0,
            times: 1000,
            action: Action::Hang,
        })
    });
    let before = rig.fake.with(|m| m.count("get.media"));
    let began = Instant::now();
    let r = pack_read(&mut s);
    assert_eq!(r.class(), Some(EC::Transient), "{r:?}");
    assert!(
        began.elapsed() >= Duration::from_millis(900),
        "three attempts of 300 ms: {:?}",
        began.elapsed()
    );
    assert!(began.elapsed() < Duration::from_secs(10));
    assert_eq!(rig.fake.with(|m| m.count("get.media")) - before, 3);
}

#[test]
fn an_upload_dropped_in_the_middle_is_retried_and_lands_whole() {
    let (rig, mut s) = case(vec![Fault {
        category: "upload",
        skip: 0,
        times: 2,
        action: Action::DropAfterBody(1000),
    }]);
    let body = data(400_000, 7);
    s.env.write(T::Pack, &id(0x42), &body).ok();
    assert_eq!(
        rig.fake
            .with(|m| m.get(&path_of(T::Pack, &id(0x42))).unwrap()),
        body
    );
}

#[test]
fn a_redirect_is_an_internal_error_and_is_never_followed() {
    let other = FakeGoogle::start();
    let (rig, mut s) = case(vec![]);
    // a redirect to somewhere that is neither allowed nor the fake: if it were followed the other
    // server would see a request
    let target: &'static str =
        Box::leak(format!("https://{}/drive/v3/files", other.addr).into_boxed_str());
    rig.fake.with(|m| {
        m.inject(Fault {
            category: "list",
            skip: 0,
            times: 1000,
            action: Action::Redirect(target),
        })
    });
    let before = rig.fake.with(|m| m.count("list"));
    let r = s.env.list(T::Index);
    assert_eq!(r.class(), Some(EC::Internal), "{r:?}");
    assert_eq!(
        rig.fake.with(|m| m.count("list")) - before,
        1,
        "not retried"
    );
    assert!(
        other.with(|m| m.log.is_empty()),
        "the redirect was followed"
    );
}

#[test]
fn only_the_two_google_hosts_are_ever_requested() {
    use hx_backup_worker::drive::rate::UploadRate;
    use hx_backup_worker::drive::transport::GoogleTransport;
    use opendal::{Buffer, HttpTransport};
    use std::sync::Arc;

    let rig = Rig::new();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let t = GoogleTransport::new(&rig.cfg.http, Arc::new(UploadRate::new()), rig.cfg.timing)
            .unwrap();
        for url in [
            "https://evil.example.com/drive/v3/files",
            "http://www.googleapis.com/drive/v3/files",
            "https://www.googleapis.com:8443/drive/v3/files",
            "https://oauth2.googleapis.com.evil.example/token",
            "https://169.254.169.254/latest/meta-data",
            "https://127.0.0.1/x",
        ] {
            let req = http::Request::get(url).body(Buffer::new()).unwrap();
            let Err(e) = t.fetch(req).await else {
                panic!("{url} was fetched")
            };
            assert!(!e.is_temporary(), "{url}: a refusal is never retried");
        }
        // an allowed host goes to the (test) address
        let req =
            http::Request::get("https://www.googleapis.com/drive/v3/about?fields=storageQuota")
                .header("authorization", "Bearer fake-access-1")
                .body(Buffer::new())
                .unwrap();
        assert_eq!(t.fetch(req).await.unwrap().status(), 200);
    });
    rig.fake.with(|m| {
        assert_eq!(
            m.log.len(),
            1,
            "only the allowed request reached the server: {:?}",
            m.log
        )
    });
}

// ---- the daily-limit gate ----

#[test]
fn the_daily_limit_gate_is_shared_by_all_requests_of_the_session() {
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    for i in 0..4u8 {
        s.env.write(T::Pack, &id(0x40 + i), &data(1000, i)).ok();
    }
    rig.fake.with(|m| {
        // all four attempts are in flight before any of them is answered
        m.delay.insert("get.media", Duration::from_millis(150));
        m.inject(Fault::status("get.media", 4, 403, "dailyLimitExceeded"));
    });
    let reqs: Vec<u64> = (0..4u8)
        .map(|i| {
            // partial reads reserve little memory, so the four run at once (a whole pack
            // reserves 96 MiB of the read budget and runs alone)
            s.env
                .request(pb::repo_request::Op::ReadPartial(pb::ReadPartial {
                    object_type: T::Pack as i32,
                    id: bytes::Bytes::copy_from_slice(&id(0x40 + i)),
                    offset: 10,
                    length: 500,
                }))
        })
        .collect();
    let began = Instant::now();
    for (i, r) in reqs.iter().enumerate() {
        assert_eq!(
            s.env.wait(*r),
            Reply::Read(data(1000, i as u8)[10..510].to_vec())
        );
    }
    assert!(
        began.elapsed() >= Duration::from_millis(150),
        "they waited at the gate"
    );
    s.env.pump_for(Duration::from_millis(300));
    let kinds = s.env.event_kinds();
    let paused: Vec<_> = s
        .env
        .events
        .iter()
        .filter(|e| e.kind == pb::EventKind::PausedDailyLimit as i32)
        .collect();
    assert_eq!(paused.len(), 1, "one pause for four failures: {kinds:?}");
    assert!(
        paused[0].until_ms > 1_700_000_000_000,
        "until_ms is a Unix time in milliseconds"
    );
    assert_eq!(s.env.count_events(pb::EventKind::Resumed), 1, "{kinds:?}");
}

#[test]
fn after_the_pause_limit_every_request_fails_with_daily_limit() {
    let rig = Rig::with(|c| {
        c.timing.daily_pause = Duration::from_millis(60);
        c.timing.max_pauses = 2;
    });
    let mut s = rig.open_session();
    s.env.create().ok();
    s.env.write(T::Pack, &id(0x40), &data(1000, 1)).ok();
    rig.fake.with(|m| {
        m.inject(Fault::status(
            "get.media",
            100_000,
            403,
            "dailyLimitExceeded",
        ))
    });
    let r = pack_read(&mut s);
    assert_eq!(r.class(), Some(EC::DailyLimit), "{r:?}");
    s.env.pump_for(Duration::from_millis(100));
    assert_eq!(
        s.env.count_events(pb::EventKind::PausedDailyLimit),
        2,
        "{:?}",
        s.env.event_kinds()
    );
    // exhausted for the session: the next request fails at its first attempt
    let before = rig.fake.with(|m| m.count("get.media"));
    let r = pack_read(&mut s);
    assert_eq!(r.class(), Some(EC::DailyLimit));
    assert_eq!(rig.fake.with(|m| m.count("get.media")) - before, 1);
}

// ---- the token ----

#[test]
fn a_revoked_refresh_token_is_auth_revoked_and_not_retried() {
    let rig = Rig::new();
    let mut s = rig.session();
    s.env.hello();
    rig.fake.with(|m| {
        m.inject(Fault {
            category: "token",
            skip: 0,
            times: 1000,
            action: Action::Raw { status: 400, body: r#"{"error":"invalid_grant","error_description":"Token has been expired or revoked."}"# },
        });
    });
    let r = s.env.open("repo", true, SERVER_A, false);
    assert_eq!(r.class(), Some(EC::AuthRevoked), "{r:?}");
    assert_eq!(rig.fake.with(|m| m.count("token")), 1);
    // every later repository request is answered, with INTERNAL: there is no repository
    assert_eq!(s.env.list(T::Pack).class(), Some(EC::Internal));
}

#[test]
fn a_token_endpoint_that_fails_twice_is_retried() {
    let rig = Rig::new();
    let mut s = rig.session();
    s.env.hello();
    rig.fake
        .with(|m| m.inject(Fault::status("token", 2, 503, "backendError")));
    s.env.open("repo", true, SERVER_A, false).ok();
    // the helper's own refresh (two failures, then success) and OpenDAL's, which is its own
    assert_eq!(rig.fake.with(|m| m.count("token")), 4);
    assert_eq!(rig.fake.with(|m| m.tokens_issued), 2);
}

#[test]
fn the_wrong_client_secret_is_rejected_by_the_token_endpoint() {
    let rig = Rig::with(|c| {
        c.client = hx_backup_worker::drive::creds::ClientConfig::parse(
            format!(r#"{{"client_id":"{CLIENT_ID}","client_secret":"not-the-secret"}}"#).as_bytes(),
        )
        .unwrap();
    });
    let mut s = rig.session();
    s.env.hello();
    assert_eq!(
        s.env.open("repo", true, SERVER_A, false).class(),
        Some(EC::AuthRevoked)
    );
    assert_eq!(rig.fake.with(|m| m.bad_refresh_tokens), 1);
}

#[test]
fn a_missing_or_malformed_token_answers_auth_revoked_and_the_helper_serves_on() {
    for content in [
        None,
        Some(r#"{"refresh_token":"short"}"#.to_owned()),
        Some(format!(
            r#"{{"refresh_token":"{REFRESH_TOKEN}","client_id":"x"}}"#
        )),
        Some("not json".to_owned()),
    ] {
        let rig = Rig::new();
        let file = rig.dir.path().join("drive-token");
        match &content {
            None => std::fs::remove_file(&file).unwrap(),
            Some(c) => std::fs::write(&file, c).unwrap(),
        }
        let mut s = rig.session();
        s.env.hello(); // the handshake still works
        let r = s.env.open("repo", true, SERVER_A, false);
        assert_eq!(r.class(), Some(EC::AuthRevoked), "{content:?}: {r:?}");
        assert_eq!(
            rig.fake.with(|m| m.log.len()),
            0,
            "no request without a token"
        );
        s.env.ping(3);
        s.env.pump_for(Duration::from_millis(100));
        assert_eq!(s.env.pongs, [3]);
        assert_eq!(s.finish(), hx_backup_worker::drive::server::End::Bye);
    }
    // no credentials directory at all
    let rig = Rig::with(|c| c.credentials_dir = None);
    let mut s = rig.session();
    s.env.hello();
    assert_eq!(
        s.env.open("repo", true, SERVER_A, false).class(),
        Some(EC::AuthRevoked)
    );
}

#[test]
fn a_missing_folder_without_create_is_not_found() {
    let rig = Rig::new();
    let mut s = rig.session();
    s.env.hello();
    assert_eq!(
        s.env.open("repo", false, SERVER_A, false).class(),
        Some(EC::NotFound)
    );
    assert!(
        rig.fake.with(|m| m.paths().is_empty()),
        "nothing was created"
    );
    // a failed OpenRepo leaves no repository: everything after it is INTERNAL
    assert_eq!(s.env.list(T::Pack).class(), Some(EC::Internal));
}
