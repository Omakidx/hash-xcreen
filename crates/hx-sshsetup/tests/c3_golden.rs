//! C3 parsing against golden lines: the exact shapes `hx-agent install --json` and `install.sh`
//! print (see `apps/hx-agent/src/install/progress.rs` tests and `tests/install_engine.rs`).

use hx_sshsetup::progress::{Line, parse_line};
use hx_sshsetup::{InstallEvent, LogStream, PairingKind, StageState};

fn event(l: &str) -> InstallEvent {
    match parse_line(l) {
        Line::Event(e) => e,
        other => panic!("not an event: {other:?}"),
    }
}

#[test]
fn stage_lines_with_and_without_counters() {
    assert_eq!(
        event(r#"{"v":1,"t":"stage","id":"config","n":7,"of":19,"state":"done","ms":123}"#),
        InstallEvent::Stage {
            id: "config".into(),
            n: Some(7),
            of: Some(19),
            state: StageState::Done,
            ms: Some(123)
        }
    );
    // install.sh's bootstrap lines have no n, of or ms.
    assert_eq!(
        event(r#"{"v":1,"t":"stage","id":"bootstrap-verify","state":"start"}"#),
        InstallEvent::Stage {
            id: "bootstrap-verify".into(),
            n: None,
            of: None,
            state: StageState::Start,
            ms: None
        }
    );
    for (s, want) in [
        ("skip", StageState::Skip),
        ("fail", StageState::Fail),
        ("deferred", StageState::Deferred),
        ("manual", StageState::Manual),
    ] {
        let l = format!(r#"{{"v":1,"t":"stage","id":"x","n":1,"of":19,"state":"{s}","ms":0}}"#);
        match event(&l) {
            InstallEvent::Stage { state, .. } => assert_eq!(state, want),
            e => panic!("{e:?}"),
        }
    }
}

#[test]
fn step_percent_255_is_unknown() {
    match event(
        r#"{"v":1,"t":"step","id":"desktop","privd_stage":"BUILD","index":3,"total":12,"step":"apt install","percent":255}"#,
    ) {
        InstallEvent::Step {
            index,
            total,
            percent,
            step,
            privd_stage,
            ..
        } => {
            assert_eq!((index, total, percent), (3, 12, None));
            assert_eq!(
                (step.as_str(), privd_stage.as_str()),
                ("apt install", "BUILD")
            );
        }
        e => panic!("{e:?}"),
    }
    match event(
        r#"{"v":1,"t":"step","id":"desktop","privd_stage":"BUILD","index":5,"total":12,"step":"Installing apps","percent":61}"#,
    ) {
        InstallEvent::Step { percent, .. } => assert_eq!(percent, Some(61)),
        e => panic!("{e:?}"),
    }
}

#[test]
fn warn_and_hostile_text() {
    assert_eq!(
        event(r#"{"v":1,"t":"warn","id":"incus","message":"old version"}"#),
        InstallEvent::Warn {
            id: "incus".into(),
            message: "old version".into()
        }
    );
    // Control and bidi characters from the remote side never reach the UI.
    match event("{\"v\":1,\"t\":\"warn\",\"id\":\"x\",\"message\":\"a\\u001b[31m\\u202Eb\"}") {
        InstallEvent::Warn { message, .. } => assert_eq!(message, "a[31mb"),
        e => panic!("{e:?}"),
    }
}

#[test]
fn the_failure_result_line() {
    let l = parse_line(
        r#"{"v":1,"t":"result","ok":false,"exit":1,"stage":"incus","code":"TOOL","message":"apt-get failed","retryable":true}"#,
    );
    match l {
        Line::Failed(f) => {
            assert_eq!(f.stage, "incus");
            assert_eq!(f.code, "TOOL");
            assert_eq!(f.message, "apt-get failed");
            assert!(f.retryable);
            assert_eq!(f.exit, 1);
        }
        o => panic!("{o:?}"),
    }
    // install.sh's die(): not retryable, except the lock (another run is finishing).
    for (code, exit, want) in [
        ("VERIFY", 10, false),
        ("PREFLIGHT", 9, false),
        ("LOCKED", 11, true),
    ] {
        let l = format!(
            r#"{{"v":1,"t":"result","ok":false,"exit":{exit},"stage":"bootstrap-x","code":"{code}","message":"m","retryable":false}}"#
        );
        match parse_line(&l) {
            Line::Failed(f) => assert_eq!(f.retryable, want, "{code}"),
            o => panic!("{o:?}"),
        }
    }
}

#[test]
fn the_success_result_line() {
    let key = "ab".repeat(32);
    let l = format!(
        r#"{{"v":1,"t":"result","ok":true,"exit":0,"install_id":"{id}","agent_version":"0.1.0","server_public_key":"{key}","addresses":["203.0.113.9","2001:db8::1"],"port":443,"desktop":{{"id":"main","path_taken":"BUILD","reason":"r","warnings":["w1"]}},"pairing":{{"kind":"code","expires_at_unix_s":900}},"port_rule":"ufw"}}"#,
        id = "a".repeat(32)
    );
    match parse_line(&l) {
        Line::Ok(r) => {
            assert_eq!(r.install_id.len(), 32);
            assert_eq!(r.server_public_key, key);
            assert_eq!(r.addresses, ["203.0.113.9", "2001:db8::1"]);
            assert_eq!(r.port, 443);
            assert_eq!(r.pairing, PairingKind::Code);
            assert_eq!(r.pairing_expires_at_unix_s, 900);
            assert_eq!(r.port_rule, "ufw");
            let d = r.desktop.expect("desktop");
            assert_eq!((d.id.as_str(), d.path_taken.as_str()), ("main", "BUILD"));
            assert_eq!(r.warnings, ["w1"]);
        }
        o => panic!("{o:?}"),
    }
    // No desktop, no pairing: the --ssh run without a token reports kind none.
    let l = format!(
        r#"{{"v":1,"t":"result","ok":true,"exit":0,"install_id":"x","agent_version":"0.1.0","server_public_key":"{key}","addresses":[],"port":8443,"desktop":null,"pairing":{{"kind":"none","expires_at_unix_s":0}},"port_rule":"none"}}"#
    );
    match parse_line(&l) {
        Line::Ok(r) => {
            assert!(r.desktop.is_none());
            assert_eq!(r.pairing, PairingKind::None);
            assert_eq!(r.port, 8443);
        }
        o => panic!("{o:?}"),
    }
}

#[test]
fn a_success_without_a_valid_key_is_not_a_success() {
    for key in ["", "abc", &"g".repeat(64)] {
        let l = format!(
            r#"{{"v":1,"t":"result","ok":true,"exit":0,"server_public_key":"{key}","addresses":[],"port":443}}"#
        );
        assert!(
            matches!(parse_line(&l), Line::Failed(f) if f.code == "PROTOCOL"),
            "{key}"
        );
    }
}

#[test]
fn tolerant_of_unknown_content() {
    // A newer installer: unknown type, unknown keys, another version.
    assert!(matches!(
        parse_line(r#"{"v":1,"t":"future","x":1}"#),
        Line::Ignored
    ));
    assert!(matches!(
        parse_line(r#"{"v":2,"t":"stage","id":"a","state":"done"}"#),
        Line::Ignored
    ));
    assert!(matches!(parse_line(r#"[1,2]"#), Line::Ignored));
    match event(r#"{"v":1,"t":"warn","id":"a","message":"m","extra":{"k":1}}"#) {
        InstallEvent::Warn { .. } => {}
        e => panic!("{e:?}"),
    }
    // Not JSON at all: kept as a log line, sanitized.
    assert_eq!(
        event("plain text\u{1b}[0m"),
        InstallEvent::Log {
            stream: LogStream::Stdout,
            text: "plain text[0m".into()
        }
    );
}
