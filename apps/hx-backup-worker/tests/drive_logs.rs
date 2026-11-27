//! No token, secret, header or URL reaches a log line (ipc.md §29 b, §34). The test installs a
//! global subscriber at TRACE (so the logs of `hyper`, `reqwest` and the helper are all captured),
//! drives the helper through success and every failure path, and searches what was logged.

mod drive_common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use drive_common::*;

struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn nothing_secret_is_ever_logged_on_any_path() {
    let buf: Arc<Mutex<Vec<u8>>> = Arc::default();
    let sub = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer({
            let buf = buf.clone();
            move || Capture(buf.clone())
        })
        .finish();
    tracing::subscriber::set_global_default(sub).expect("this binary has one test");

    // success, with the token endpoint, uploads, reads and deletes
    let rig = Rig::new();
    let mut s = rig.open_session();
    s.env.create().ok();
    s.env.write(T::Pack, &id(0x40), &data(5000, 1)).ok();
    s.env.read_full(T::Pack, &id(0x40)).ok();
    s.env.quota().ok();
    s.env.remove(T::Pack, &id(0x40)).ok();
    // errors of every class
    for (cat, status, reason) in [
        ("list", 429u16, ""),
        ("list", 403, "rateLimitExceeded"),
        ("list", 403, "dailyLimitExceeded"),
        ("list", 403, "storageQuotaExceeded"),
        ("list", 403, "appNotAuthorizedToFile"),
        ("list", 401, "authError"),
        ("list", 500, "backendError"),
        ("get.media", 404, "notFound"),
    ] {
        rig.fake.with(|m| {
            m.clear_faults();
            m.inject(Fault::status(cat, 30, status, reason));
        });
        let _ = s.env.list(T::Index);
        let _ = s.env.read_full(T::Pack, &id(0x41));
    }
    rig.fake.with(|m| {
        m.clear_faults();
        m.inject(Fault { category: "list", skip: 0, times: 3, action: Action::Drop });
        m.inject(Fault { category: "get.media", skip: 0, times: 3, action: Action::TruncateBody });
    });
    let _ = s.env.list(T::Index);
    let _ = s.env.read_full(T::Pack, &id(0x40));
    drop(s);

    // revoked token, wrong secret, missing token
    let rig = Rig::new();
    rig.fake.with(|m| {
        m.inject(Fault {
            category: "token",
            skip: 0,
            times: 10,
            action: Action::Raw { status: 400, body: r#"{"error":"invalid_grant"}"# },
        });
    });
    let mut s = rig.session();
    s.env.hello();
    let _ = s.env.open("repo", true, SERVER_A, false);
    drop(s);
    let rig = Rig::with(|c| {
        c.client = hx_backup_worker::drive::creds::ClientConfig::parse(
            format!(r#"{{"client_id":"{CLIENT_ID}","client_secret":"wrong-secret-value"}}"#).as_bytes(),
        )
        .unwrap();
    });
    let mut s = rig.session();
    s.env.hello();
    let _ = s.env.open("repo", true, SERVER_A, false);
    drop(s);
    let rig = Rig::new();
    std::fs::remove_file(rig.dir.path().join("drive-token")).unwrap();
    let mut s = rig.session();
    s.env.hello();
    let _ = s.env.open("repo", true, SERVER_A, false);
    drop(s);
    std::thread::sleep(Duration::from_millis(300));

    let log = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
    assert!(log.contains("drive"), "the capture works: {} bytes", log.len());
    assert!(log.contains("hyper_util"), "TRACE of the HTTP stack is captured too");
    for secret in [
        REFRESH_TOKEN,
        CLIENT_SECRET,
        "wrong-secret-value",
        "fake-access-",
        "refresh_token=",
        "client_secret=",
        "Bearer",
        "uthorization",
        "oauth2.googleapis.com/token",
        "googleapis.com/drive",
        "grant_type",
    ] {
        assert!(!log.contains(secret), "{secret:?} was logged:\n{}", log.lines().filter(|l| l.contains(secret)).take(3).collect::<Vec<_>>().join("\n"));
    }
}
