//! Every command against the real servers: the real gateway admin server (devices, pairing,
//! verifiers, the setup mirror) and the real privd `Daemon` (host and desktop commands, setup
//! phase, lockout, audit), with the CLI's own client in between. See `cli_common` for how the
//! `Admin` role reaches the daemon without root.

mod cli_common;

use std::sync::Arc;

use cli_common::*;
use hx_agent::privd::daemon::Ctx;
use hx_agent::privd::testing::request;
use hx_crypto::{PairClientOptions, PairingCredential, PairingToken, pair_device};
use hx_ipc::privd::pb::{self, Role, request::Command, response::Result as R};
use hx_ipc::secret::Secret;
use hx_transport::TransportPreference;
use serde_json::Value;

use gateway_common::{Env as GwEnv, new_key, within};

fn device_hex(k: &Arc<hx_crypto::IdentityKey>) -> String {
    GwEnv::id_of(k)
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A prefix of 4 hex digits that no listed device starts with.
fn unused_prefix(ids: &[String]) -> String {
    (0..=0xffffu32)
        .map(|n| format!("{n:04x}"))
        .find(|p| !ids.iter().any(|i| i.starts_with(p)))
        .unwrap()
}

async fn daemon_call(
    w: &World,
    role: Role,
    command: Command,
    secrets: &[(pb::SecretKind, &[u8])],
) -> pb::Response {
    let mut req = request(1, command);
    req.secret_slots = secrets
        .iter()
        .enumerate()
        .map(|(i, (k, s))| pb::SecretSlot {
            slot: i as u32,
            kind: *k as i32,
            length: s.len() as u32,
            ..Default::default()
        })
        .collect();
    let mut ctx = Ctx::new(role);
    ctx.secrets = secrets
        .iter()
        .map(|(_, s)| Some(Secret::new(s.to_vec())))
        .collect();
    w.privd.daemon.handle(req, ctx).await
}

async fn pair_with_text(w: &World, text: &str, name: &str) {
    let device = new_key();
    let cred = PairingCredential::parse(text).expect("a credential");
    let paired = within(pair_device(
        &w.gw.target(TransportPreference::Quic),
        &device,
        &cred,
        &PairClientOptions {
            preference: TransportPreference::Quic,
            device_name: name.into(),
            ..Default::default()
        },
    ))
    .await
    .expect("pairing with what the CLI installed");
    paired.finish().await;
}

// ------------------------------------------------------------------------------------- status

#[tokio::test]
async fn status_reports_both_daemons() {
    let w = World::start().await;
    let r = cli(&w.cfg, &["status"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    for needle in [
        "hx-privd",
        "phase UNINITIALIZED",
        "hx-gatewayd",
        "listening",
        "setup window closed",
        "nothing needs attention",
        "devices",
    ] {
        assert!(
            r.stdout.contains(needle),
            "{needle:?} missing from {}",
            r.stdout
        );
    }
    let j = cli(&w.cfg, &["status", "--json"], &[], &[]).await;
    assert_eq!(j.code, 0);
    let v = j.json();
    assert_eq!(v["ok"], true);
    assert_eq!(v["command"], "status");
    let d = &v["data"];
    assert_eq!(d["cli_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(d["privd"]["reachable"], true);
    assert_eq!(d["privd"]["phase"], "UNINITIALIZED");
    assert_eq!(d["gatewayd"]["reachable"], true);
    assert_eq!(d["gatewayd"]["session_link"], "UP");
    assert_eq!(d["gatewayd"]["setup_window"]["open"], false);
    assert_eq!(d["devices"]["total"], 0);
    assert_eq!(d["lockouts"]["pin"], false);
}

#[tokio::test]
async fn status_still_reports_privd_when_gatewayd_is_down_and_exits_3() {
    let w = World::start().await;
    let mut cfg = w.cfg.clone();
    cfg.admin_socket = w.dir.path().join("no-such-admin.sock");
    let r = cli(&cfg, &["status"], &[], &[]).await;
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.stdout.contains("hx-privd"), "{}", r.stdout);
    assert!(
        r.stdout.contains("hx-gatewayd    not reachable"),
        "{}",
        r.stdout
    );
    let v = cli(&cfg, &["status", "--json"], &[], &[]).await.json();
    assert_eq!(v["ok"], false);
    assert_eq!(v["data"]["privd"]["reachable"], true);
    assert_eq!(v["data"]["gatewayd"]["reachable"], false);
}

#[tokio::test]
async fn status_shows_the_desktop_and_a_locked_pin() {
    let w = World::start().await;
    w.add_desktop();
    // Open the window so that the gateway role may call PepperVerify, then fail it into a lock.
    assert_eq!(cli(&w.cfg, &["setup", "begin"], &[], &[]).await.code, 0);
    for _ in 0..12 {
        let _ = daemon_call(
            &w,
            Role::Gateway,
            Command::PepperVerify(pb::PepperVerifyRequest {
                purpose: pb::LockoutPurpose::Pin as i32,
                expected_verifier: vec![9u8; 32].into(),
            }),
            &[(pb::SecretKind::MacInput, &[1u8; 32])],
        )
        .await;
    }
    let r = cli(&w.cfg, &["status"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert!(
        r.stdout.contains("desktop      main running (user alice"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("NEEDS ATTENTION: PIN_LOCKED"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("pin LOCKED"), "{}", r.stdout);
    assert!(r.stdout.contains("setup window open until"), "{}", r.stdout);
    let v = cli(&w.cfg, &["status", "--json"], &[], &[]).await.json();
    assert_eq!(v["data"]["lockouts"]["pin"], true);
    assert_eq!(v["data"]["privd"]["desktops"][0]["id"], "main");
    assert_eq!(v["data"]["gatewayd"]["setup_window"]["open"], true);
}

// ------------------------------------------------------------------------------------ devices

#[tokio::test]
async fn devices_list_revoke_and_reinstate_by_prefix() {
    let w = World::start().await;
    let (a, b) = (new_key(), new_key());
    w.gw.pair(&a, "alice-laptop").await;
    w.gw.pair(&b, "bob-phone").await;
    let (ha, hb) = (device_hex(&a), device_hex(&b));

    let r = cli(&w.cfg, &["devices", "list"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.stdout.contains("alice-laptop") && r.stdout.contains("bob-phone"));
    assert!(r.stdout.contains(&ha[..12]) && r.stdout.contains(&hb[..12]));

    // Revoke alice by the shortest prefix that is unique.
    let n = (4..=32).find(|n| !hb.starts_with(&ha[..*n])).unwrap();
    let r = cli(&w.cfg, &["devices", "revoke", &ha[..n]], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert!(
        r.stdout.contains("revoked") && r.stdout.contains("alice-laptop"),
        "{}",
        r.stdout
    );
    let v = cli(&w.cfg, &["devices", "list", "--json"], &[], &[])
        .await
        .json();
    let state_of = |name: &str| {
        v["data"]["devices"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == name)
            .unwrap()["state"]
            .clone()
    };
    assert_eq!(state_of("alice-laptop"), "REVOKED");
    assert_eq!(state_of("bob-phone"), "ACTIVE");
    // The gateway recorded the revocation in privd's audit path.
    assert!(
        w.gw.privd
            .wait_for(|s| s
                .events
                .iter()
                .any(|e| e.0 == pb::AuditEvent::DeviceRevoked))
            .await
    );

    // Reinstate with the full id (upper case works).
    let r = cli(
        &w.cfg,
        &["devices", "reinstate", &ha.to_uppercase()],
        &[],
        &["yes"],
    )
    .await;
    assert_eq!(r.code, 0, "{r:?}");
    let v = cli(&w.cfg, &["devices", "list", "--json"], &[], &[])
        .await
        .json();
    assert_eq!(state_of_value(&v, "alice-laptop"), "ACTIVE");
}

fn state_of_value(v: &Value, name: &str) -> Value {
    v["data"]["devices"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["name"] == name)
        .unwrap()["state"]
        .clone()
}

#[tokio::test]
async fn an_unknown_or_malformed_prefix_changes_nothing() {
    let w = World::start().await;
    let a = new_key();
    w.gw.pair(&a, "alice").await;
    let ha = device_hex(&a);
    let nope = unused_prefix(std::slice::from_ref(&ha));
    let r = cli(&w.cfg, &["devices", "revoke", &nope], &[], &[]).await;
    assert_eq!(r.code, 5, "{r:?}");
    assert!(
        r.stderr.contains("no device id starts with"),
        "{}",
        r.stderr
    );
    for bad in ["ab", "zzzz1111", "aa bb"] {
        assert_eq!(
            cli(&w.cfg, &["devices", "revoke", bad], &[], &[])
                .await
                .code,
            2,
            "{bad}"
        );
    }
    let v = cli(&w.cfg, &["devices", "list", "--json"], &[], &[])
        .await
        .json();
    assert_eq!(state_of_value(&v, "alice"), "ACTIVE");
}

#[tokio::test]
async fn an_ambiguous_prefix_is_an_error_that_lists_the_candidates_and_changes_nothing() {
    let w = World::start().await;
    // Two keys whose ids share the first four hex digits (a few hundred keys at most).
    let mut seen: std::collections::HashMap<String, Arc<hx_crypto::IdentityKey>> =
        Default::default();
    let (a, b) = loop {
        let k = new_key();
        let h = device_hex(&k)[..4].to_owned();
        if let Some(prev) = seen.insert(h, k.clone()) {
            break (prev, k);
        }
    };
    w.gw.pair(&a, "first-device").await;
    w.gw.pair(&b, "second-device").await;
    let (ha, hb) = (device_hex(&a), device_hex(&b));
    let r = cli(&w.cfg, &["devices", "revoke", &ha[..4]], &[], &[]).await;
    assert_eq!(r.code, 5, "{r:?}");
    assert!(r.stderr.contains("ambiguous"), "{}", r.stderr);
    assert!(r.stderr.contains("first-device") && r.stderr.contains("second-device"));
    assert!(r.stderr.contains(&ha) && r.stderr.contains(&hb));
    let v = cli(&w.cfg, &["devices", "list", "--json"], &[], &[])
        .await
        .json();
    assert_eq!(state_of_value(&v, "first-device"), "ACTIVE");
    assert_eq!(state_of_value(&v, "second-device"), "ACTIVE");
    // The JSON form says the same thing.
    let j = cli(&w.cfg, &["devices", "revoke", &ha[..4], "--json"], &[], &[]).await;
    assert_eq!(j.code, 5);
    assert_eq!(j.json()["error"]["code"], "NOT_FOUND");
    // A longer prefix resolves it.
    let n = (4..=32).find(|n| ha[..*n] != hb[..*n]).unwrap();
    assert_eq!(
        cli(&w.cfg, &["devices", "revoke", &ha[..n]], &[], &[])
            .await
            .code,
        0
    );
}

// ------------------------------------------------------------------------------------ pairing

#[tokio::test]
async fn pairing_code_installs_a_code_that_pairs() {
    let w = World::start().await;
    let r = cli(&w.cfg, &["pairing", "code", "--json"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    let v = r.json();
    let code = v["data"]["code"].as_str().unwrap().to_owned();
    assert_eq!(code.len(), 9, "{code}");
    assert!(v["data"]["expires_at_unix_s"].as_u64().unwrap() > hx_agent::cli::system_now());
    pair_with_text(&w, &code, "from-code").await;
    let l = cli(&w.cfg, &["devices", "list"], &[], &[]).await;
    assert!(l.stdout.contains("from-code"), "{}", l.stdout);
    // Human form shows the code once, with its lifetime.
    let h = cli(&w.cfg, &["pairing", "code", "--ttl", "5m"], &[], &[]).await;
    assert!(h.stdout.contains("pairing code: "), "{}", h.stdout);
}

#[tokio::test]
async fn pairing_token_from_the_hidden_prompt_is_installed_and_pairs() {
    let w = World::start().await;
    let token = PairingToken::generate().unwrap();
    let text = token.to_text();
    let r = cli(&w.cfg, &["pairing", "token"], &[text.as_bytes()], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert!(
        r.asked
            .iter()
            .any(|q| q.starts_with("secret: Pairing token")),
        "{:?}",
        r.asked
    );
    assert!(!r.stdout.contains(text.as_str()) && !r.stderr.contains(text.as_str()));
    pair_with_text(&w, &text, "from-token").await;
}

#[tokio::test]
async fn generated_token_is_shown_once_and_pairs() {
    let w = World::start().await;
    let r = cli(
        &w.cfg,
        &["pairing", "token", "--generate", "--json"],
        &[],
        &[],
    )
    .await;
    assert_eq!(r.code, 0, "{r:?}");
    let v = r.json();
    let t = v["data"]["token"].as_str().unwrap().to_owned();
    assert!(t.starts_with("hxt1-"));
    assert_eq!(r.stdout.matches(&t).count(), 1, "the token appears once");
    pair_with_text(&w, &t, "from-generated").await;
    // Human form too.
    let h = cli(&w.cfg, &["pairing", "token", "--generate"], &[], &[]).await;
    assert!(h.stdout.contains("shown once"), "{}", h.stdout);
}

#[tokio::test]
async fn pairing_token_in_argv_works_with_a_loud_warning() {
    let w = World::start().await;
    let token = PairingToken::generate().unwrap();
    let text = token.to_text();
    let r = cli(&w.cfg, &["pairing", "token", "--token", &text], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.stderr.contains("WEAKER"), "{}", r.stderr);
    assert!(r.stderr.contains("process list") && r.stderr.contains("shell history"));
    assert!(!r.stdout.contains(text.as_str()) && !r.stderr.contains(text.as_str()));
    assert!(
        r.asked.is_empty(),
        "nothing is asked when the token is given"
    );
    pair_with_text(&w, &text, "from-argv").await;
}

#[tokio::test]
async fn a_malformed_token_is_refused_before_it_is_sent() {
    let w = World::start().await;
    let r = cli(&w.cfg, &["pairing", "token"], &[b"not-a-token"], &[]).await;
    assert_eq!(r.code, 2, "{r:?}");
    let r = cli(&w.cfg, &["pairing", "token"], &[], &[]).await;
    assert_eq!(r.code, 8, "no terminal, no secret: {r:?}");
}

// ----------------------------------------------------------------------------------- pin

#[tokio::test]
async fn pin_set_builds_a_verifier_that_privd_accepts() {
    let w = World::start().await;
    let a = new_key();
    w.gw.pair(&a, "alice").await;
    let r = cli(&w.cfg, &["pin", "set"], &[b"482913", b"482913"], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert!(w.gw.gw.verifiers().has_pin());
    let rec =
        w.gw.gw
            .verifiers()
            .pin_for(&GwEnv::id_of(&a))
            .expect("a PIN verifier");
    // The record is Argon2id(PIN) peppered by the real privd: privd must say yes to it.
    let input = rec.derive(b"482913").unwrap();
    let yes = daemon_call(
        &w,
        Role::Admin,
        Command::PepperVerify(pb::PepperVerifyRequest {
            purpose: pb::LockoutPurpose::Pin as i32,
            expected_verifier: rec.expected_mac().to_vec().into(),
        }),
        &[(pb::SecretKind::MacInput, &input[..])],
    )
    .await;
    assert!(
        matches!(yes.result, Some(R::PepperVerify(ref v)) if v.ok),
        "{yes:?}"
    );
    let wrong = rec.derive(b"111111").unwrap();
    let no = daemon_call(
        &w,
        Role::Admin,
        Command::PepperVerify(pb::PepperVerifyRequest {
            purpose: pb::LockoutPurpose::Pin as i32,
            expected_verifier: rec.expected_mac().to_vec().into(),
        }),
        &[(pb::SecretKind::MacInput, &wrong[..])],
    )
    .await;
    assert!(
        matches!(no.result, Some(R::PepperVerify(ref v)) if !v.ok),
        "{no:?}"
    );
    // Neither the CLI's output nor the questions it asked contain the PIN.
    for s in [&r.stdout, &r.stderr] {
        assert!(!s.contains("482913"));
    }
    assert!(r.asked.iter().all(|q| !q.contains("482913")));
}

#[tokio::test]
async fn pin_set_for_one_device_by_prefix() {
    let w = World::start().await;
    let (a, b) = (new_key(), new_key());
    w.gw.pair(&a, "alice").await;
    w.gw.pair(&b, "bob").await;
    let (ha, hb) = (device_hex(&a), device_hex(&b));
    let n = (4..=32).find(|n| ha[..*n] != hb[..*n]).unwrap();
    let r = cli(
        &w.cfg,
        &["pin", "set", "--device", &ha[..n]],
        &[b"135790", b"135790"],
        &[],
    )
    .await;
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.stdout.contains("alice"), "{}", r.stdout);
    let own = w.gw.gw.verifiers().pin_for(&GwEnv::id_of(&a));
    assert!(own.is_some());
    assert!(
        w.gw.gw.verifiers().pin_for(&GwEnv::id_of(&b)).is_none(),
        "bob has no PIN of his own, and there is no shared one"
    );
}

#[tokio::test]
async fn pin_set_refuses_differing_entries_and_bad_pins_without_changing_anything() {
    let w = World::start().await;
    let r = cli(&w.cfg, &["pin", "set"], &[b"482913", b"482914"], &[]).await;
    assert_eq!(r.code, 8, "{r:?}");
    let r = cli(&w.cfg, &["pin", "set"], &[b"12ab", b"12ab"], &[]).await;
    assert_eq!(r.code, 2, "{r:?}");
    let r = cli(&w.cfg, &["pin", "set"], &[b"123", b"123"], &[]).await;
    assert_eq!(r.code, 2, "{r:?}");
    assert!(!w.gw.gw.verifiers().has_pin());
    assert!(
        w.privd
            .audit
            .lines()
            .iter()
            .all(|l| !l.contains("PepperEnrol")),
        "nothing reached privd"
    );
}

#[tokio::test]
async fn pin_reset_lockout_asks_clears_everything_and_is_audited() {
    let w = World::start().await;
    assert_eq!(cli(&w.cfg, &["setup", "begin"], &[], &[]).await.code, 0);
    for _ in 0..12 {
        let _ = daemon_call(
            &w,
            Role::Gateway,
            Command::PepperVerify(pb::PepperVerifyRequest {
                purpose: pb::LockoutPurpose::Pin as i32,
                expected_verifier: vec![9u8; 32].into(),
            }),
            &[(pb::SecretKind::MacInput, &[1u8; 32])],
        )
        .await;
    }
    let locked = |v: &Value| v["data"]["lockouts"]["pin"].as_bool().unwrap();
    assert!(locked(
        &cli(&w.cfg, &["status", "--json"], &[], &[]).await.json()
    ));

    // Declined: nothing changes.
    let r = cli(&w.cfg, &["pin", "reset-lockout"], &[], &["no"]).await;
    assert_eq!(r.code, 8, "{r:?}");
    assert!(r.stderr.contains("WHOLE failure history"), "{}", r.stderr);
    assert!(
        r.asked.iter().any(|q| q.contains("Type 'yes'")),
        "{:?}",
        r.asked
    );
    assert!(locked(
        &cli(&w.cfg, &["status", "--json"], &[], &[]).await.json()
    ));
    assert!(
        w.privd
            .audit
            .lines()
            .iter()
            .all(|l| !l.contains("ResetLockout"))
    );

    // Typed confirmation.
    let r = cli(&w.cfg, &["pin", "reset-lockout"], &[], &["yes"]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.stdout.contains("audit log"), "{}", r.stdout);
    assert!(!locked(
        &cli(&w.cfg, &["status", "--json"], &[], &[]).await.json()
    ));
    let audit = w.privd.audit.lines();
    assert!(
        audit
            .iter()
            .any(|l| l.contains("ResetLockout") && l.contains("role=admin")),
        "{audit:?}"
    );

    // --yes skips the question.
    let r = cli(
        &w.cfg,
        &["pin", "reset-lockout", "--purpose", "password", "--yes"],
        &[],
        &[],
    )
    .await;
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.asked.is_empty(), "{:?}", r.asked);
    // An answer other than the exact word is a no.
    let r = cli(&w.cfg, &["pin", "reset-lockout"], &[], &["y"]).await;
    assert_eq!(r.code, 8);
}

// ---------------------------------------------------------------------------------- setup

#[tokio::test]
async fn setup_window_is_driven_in_privd_and_mirrored_in_gatewayd() {
    let w = World::start().await;
    let r = cli(
        &w.cfg,
        &["setup", "begin", "--for", "1h", "--json"],
        &[],
        &[],
    )
    .await;
    assert_eq!(r.code, 0, "{r:?}");
    let v = r.json();
    assert_eq!(v["data"]["open"], true);
    let expires = v["data"]["expires_at_unix_s"].as_u64().unwrap();
    // privd's own clock (the harness runs it on a manual clock at 1_800_000_000).
    assert_eq!(expires, 1_800_000_000 + 3600);
    let s = cli(&w.cfg, &["status", "--json"], &[], &[]).await.json();
    assert_eq!(s["data"]["privd"]["phase"], "SETUP_OPEN");
    assert_eq!(s["data"]["gatewayd"]["setup_window"]["open"], true);

    let r = cli(&w.cfg, &["setup", "extend", "30m"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");

    // No ready desktop: privd refuses to finish, and the mirror stays open.
    let r = cli(&w.cfg, &["setup", "finish"], &[], &[]).await;
    assert_eq!(r.code, 4, "{r:?}");
    let s = cli(&w.cfg, &["status", "--json"], &[], &[]).await.json();
    assert_eq!(s["data"]["gatewayd"]["setup_window"]["open"], true);

    w.add_desktop();
    let r = cli(&w.cfg, &["setup", "finish"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    let s = cli(&w.cfg, &["status", "--json"], &[], &[]).await.json();
    assert_eq!(s["data"]["privd"]["phase"], "READY");
    assert_eq!(s["data"]["gatewayd"]["setup_window"]["open"], false);
}

#[tokio::test]
async fn setup_finish_force_closes_without_a_desktop_and_extend_needs_an_open_window() {
    let w = World::start().await;
    let r = cli(&w.cfg, &["setup", "extend", "30m"], &[], &[]).await;
    assert_eq!(r.code, 4, "{r:?}");
    assert_eq!(cli(&w.cfg, &["setup", "begin"], &[], &[]).await.code, 0);
    assert_eq!(
        cli(&w.cfg, &["setup", "finish", "--force"], &[], &[])
            .await
            .code,
        0
    );
    let s = cli(&w.cfg, &["status", "--json"], &[], &[]).await.json();
    assert_eq!(s["data"]["privd"]["phase"], "READY");
    assert_eq!(s["data"]["gatewayd"]["setup_window"]["open"], false);
    // Out-of-range durations never reach a daemon.
    assert_eq!(
        cli(&w.cfg, &["setup", "begin", "--for", "10"], &[], &[])
            .await
            .code,
        2
    );
    assert_eq!(
        cli(&w.cfg, &["setup", "begin", "--for", "25h"], &[], &[])
            .await
            .code,
        2
    );
}

// -------------------------------------------------------------------------------- desktop

#[tokio::test]
async fn desktop_power_and_limits() {
    let w = World::start().await;
    w.add_desktop();
    assert_eq!(cli(&w.cfg, &["setup", "begin"], &[], &[]).await.code, 0);
    let r = cli(&w.cfg, &["desktop", "stop", "--json"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.json()["data"]["running"], false);
    assert_eq!(
        w.privd
            .incus
            .with(|s| s.instances["hx-main"].status.clone()),
        "Stopped"
    );
    let r = cli(&w.cfg, &["desktop", "start", "--json"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.json()["data"]["running"], true);
    let r = cli(&w.cfg, &["desktop", "restart", "--force"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");

    // Showing limits changes nothing; a partial change keeps the other fields.
    let r = cli(&w.cfg, &["desktop", "limits", "--json"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    let before = r.json()["data"]["limits"].clone();
    assert_eq!(before["cpu"], 2);
    let r = cli(
        &w.cfg,
        &["desktop", "limits", "--memory-mib", "3072", "--json"],
        &[],
        &[],
    )
    .await;
    assert_eq!(r.code, 0, "{r:?}");
    let after = r.json()["data"]["limits"].clone();
    assert_eq!(after["memory_mib"], 3072);
    assert_eq!(after["cpu"], before["cpu"]);
    assert_eq!(after["disk_gib"], before["disk_gib"]);
    let again = cli(&w.cfg, &["desktop", "limits", "--json"], &[], &[])
        .await
        .json();
    assert_eq!(again["data"]["limits"]["memory_mib"], 3072);

    // A value outside privd's bounds is refused by privd (exit 4), not by the CLI.
    let r = cli(&w.cfg, &["desktop", "limits", "--cpu", "4096"], &[], &[]).await;
    assert_eq!(r.code, 4, "{r:?}");
    // An unknown desktop id.
    let r = cli(&w.cfg, &["desktop", "stop", "--desktop", "ghost"], &[], &[]).await;
    assert_eq!(r.code, 5, "{r:?}");
}

#[tokio::test]
async fn desktop_password_goes_to_privd_as_a_secret_and_refreshes_gatewayds_verifier() {
    let w = World::start().await;
    w.add_desktop();
    let pw: &[u8] = b"Correct-Horse-Battery-9";
    let r = cli(&w.cfg, &["desktop", "password"], &[pw, pw], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert!(r.stdout.contains("verifier is refreshed"), "{}", r.stdout);
    // privd ran chpasswd for the desktop; the password is in no argv, no audit line, no output.
    let needle = "Correct-Horse";
    assert!(
        w.privd
            .incus
            .with(|s| s.execs.iter().any(|e| e.contains("chpasswd")))
    );
    assert!(
        w.privd
            .incus
            .with(|s| s.execs.iter().all(|e| !e.contains(needle)))
    );
    assert!(w.privd.audit.lines().iter().all(|l| !l.contains(needle)));
    for s in [&r.stdout, &r.stderr] {
        assert!(!s.contains(needle));
    }
    assert!(r.asked.iter().all(|q| !q.contains(needle)));
    // gatewayd holds a verifier of that password, peppered by privd's pepper.
    let rec = w.gw.gw.verifiers().password().expect("a password verifier");
    let input = rec.derive(pw).unwrap();
    let ok = daemon_call(
        &w,
        Role::Admin,
        Command::PepperVerify(pb::PepperVerifyRequest {
            purpose: pb::LockoutPurpose::Password as i32,
            expected_verifier: rec.expected_mac().to_vec().into(),
        }),
        &[(pb::SecretKind::MacInput, &input[..])],
    )
    .await;
    assert!(
        matches!(ok.result, Some(R::PepperVerify(ref v)) if v.ok),
        "{ok:?}"
    );
}

#[tokio::test]
async fn desktop_password_verifier_only_changes_no_linux_password() {
    let w = World::start().await;
    w.add_desktop();
    let pw: &[u8] = b"Already-Set-Password-1";
    let r = cli(
        &w.cfg,
        &["desktop", "password", "--verifier-only"],
        &[pw, pw],
        &[],
    )
    .await;
    assert_eq!(r.code, 0, "{r:?}");
    assert!(
        w.privd
            .incus
            .with(|s| s.execs.iter().all(|e| !e.contains("chpasswd")))
    );
    assert!(w.gw.gw.verifiers().password().is_some());
}

#[tokio::test]
async fn desktop_password_with_differing_entries_or_a_bad_password_changes_nothing() {
    let w = World::start().await;
    w.add_desktop();
    let r = cli(
        &w.cfg,
        &["desktop", "password"],
        &[b"one-password-1", b"one-password-2"],
        &[],
    )
    .await;
    assert_eq!(r.code, 8, "{r:?}");
    let r = cli(
        &w.cfg,
        &["desktop", "password"],
        &[b"bad\0pw", b"bad\0pw"],
        &[],
    )
    .await;
    assert_eq!(r.code, 2, "{r:?}");
    assert!(
        w.privd
            .incus
            .with(|s| s.execs.iter().all(|e| !e.contains("chpasswd")))
    );
    assert!(w.gw.gw.verifiers().password().is_none());
}

// ------------------------------------------------------------------------------------ docker

#[tokio::test]
async fn docker_enable_asks_first_and_reports_privds_outcome() {
    let w = World::start().await;
    w.add_desktop();
    // Declined: privd is never called.
    let r = cli(&w.cfg, &["docker", "enable"], &[], &["no"]).await;
    assert_eq!(r.code, 8, "{r:?}");
    assert!(r.stderr.contains("LOWERS the isolation"), "{}", r.stderr);
    assert!(
        w.privd
            .audit
            .lines()
            .iter()
            .all(|l| !l.contains("EnableDocker"))
    );
    // Confirmed: the fake Incus is older than Docker needs, a domain outcome, exit 4.
    let r = cli(&w.cfg, &["docker", "enable"], &[], &["yes"]).await;
    assert_eq!(r.code, 4, "{r:?}");
    assert!(
        r.stdout.contains("was NOT enabled") && r.stdout.contains("Incus 6.0.0"),
        "{}",
        r.stdout
    );
    let j = cli(&w.cfg, &["docker", "enable", "--yes", "--json"], &[], &[]).await;
    assert_eq!(j.code, 4);
    assert_eq!(j.json()["data"]["outcome"], "UNSUPPORTED_INCUS");
    assert_eq!(j.json()["ok"], false);
    assert!(j.asked.is_empty());
    assert!(
        w.privd
            .audit
            .lines()
            .iter()
            .any(|l| l.contains("EnableDocker") && l.contains("role=admin"))
    );
}

#[tokio::test]
async fn docker_disable_calls_privd() {
    let w = World::start().await;
    w.add_desktop();
    let r = cli(&w.cfg, &["docker", "disable", "--json"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.json()["data"]["docker"], "OFF");
}

// ---------------------------------------------------------------------------------- snapshots

#[tokio::test]
async fn snapshots_list_create_delete() {
    let w = World::start().await;
    w.add_desktop();
    assert_eq!(cli(&w.cfg, &["setup", "begin"], &[], &[]).await.code, 0);
    let r = cli(&w.cfg, &["snapshots", "list"], &[], &[]).await;
    assert!(r.stdout.contains("no snapshots"), "{}", r.stdout);
    let r = cli(&w.cfg, &["snapshots", "create", "--json"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    let name = r.json()["data"]["snapshot"]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(hx_ipc::privd::is_valid_snapshot_name(&name), "{name}");
    let l = cli(&w.cfg, &["snapshots", "list"], &[], &[]).await;
    assert!(
        l.stdout.contains(&name) && l.stdout.contains("manual"),
        "{}",
        l.stdout
    );
    let d = cli(&w.cfg, &["snapshots", "delete", &name], &[], &[]).await;
    assert_eq!(d.code, 0, "{d:?}");
    let l = cli(&w.cfg, &["snapshots", "list", "--json"], &[], &[])
        .await
        .json();
    assert_eq!(l["data"]["snapshots"].as_array().unwrap().len(), 0);
    // A malformed name never reaches privd.
    assert_eq!(
        cli(&w.cfg, &["snapshots", "delete", "user-snapshot"], &[], &[])
            .await
            .code,
        2
    );
}

// -------------------------------------------------------------------------------------- logs

#[tokio::test]
async fn logs_show_the_journal_and_the_audit_log() {
    let w = World::start().await;
    let data = w.dir.path().join("journal.txt");
    std::fs::write(&data, "2026-11-21T10:00:00+0000 host hx-privd[1]: started\n2026-11-21T10:00:01+0000 host hx-gatewayd[2]: listening\n").unwrap();
    let argv = w.dir.path().join("argv.txt");
    let mut cfg = w.cfg.clone();
    cfg.journalctl = write_script(
        w.dir.path(),
        "journalctl-fake",
        &format!(
            "printf '%s\\n' \"$@\" > '{}'\ncat '{}'\n",
            argv.display(),
            data.display()
        ),
    );
    write_audit(
        &cfg.audit_log,
        "ts=1 role=admin cmd=ResetLockout outcome=OK\nts=2 role=gateway cmd=PepperVerify outcome=OK\n",
    );
    let r = cli(&cfg, &["logs", "-n", "7"], &[], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert!(
        r.stdout.contains("hx-privd[1]: started") && r.stdout.contains("cmd=ResetLockout"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("== journal") && r.stdout.contains("== audit log =="));
    // The program ran with a fixed argv and the number we gave, nothing else.
    let recorded = std::fs::read_to_string(&argv).unwrap();
    assert_eq!(
        recorded.lines().collect::<Vec<_>>(),
        hx_agent_journal_argv(7)
    );
    let j = cli(&cfg, &["logs", "--audit", "--json", "-n", "1"], &[], &[])
        .await
        .json();
    assert!(j["data"]["journal"].is_null());
    assert_eq!(j["data"]["audit"].as_array().unwrap().len(), 1);
    assert!(
        j["data"]["audit"][0]
            .as_str()
            .unwrap()
            .contains("PepperVerify")
    );
    // No audit log yet: not an error.
    std::fs::remove_file(&cfg.audit_log).unwrap();
    let r = cli(&cfg, &["logs", "--audit"], &[], &[]).await;
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("(no entries)"));
}

fn hx_agent_journal_argv(n: u32) -> Vec<String> {
    vec![
        "--no-pager".into(),
        "--output=short-iso".into(),
        "--lines".into(),
        n.to_string(),
        "_SYSTEMD_UNIT=hx-privd.service".into(),
        "_UID=0".into(),
        "+".into(),
        "_SYSTEMD_UNIT=hx-gatewayd.service".into(),
    ]
}

#[tokio::test]
async fn logs_refuse_an_audit_log_that_is_not_ours() {
    let w = World::start().await;
    let mut cfg = w.cfg.clone();
    // A symlink in place of the file.
    let real = w.dir.path().join("elsewhere.log");
    std::fs::write(&real, "forged\n").unwrap();
    std::os::unix::fs::symlink(&real, &cfg.audit_log).unwrap();
    let r = cli(&cfg, &["logs", "--audit"], &[], &[]).await;
    assert_eq!(r.code, 1, "{r:?}");
    assert!(!r.stdout.contains("forged"));
    std::fs::remove_file(&cfg.audit_log).unwrap();
    // A file owned by someone else (the check is against the configured owner).
    write_audit(&cfg.audit_log, "forged\n");
    cfg.audit_owner_uid = my_uid() + 1;
    let r = cli(&cfg, &["logs", "--audit"], &[], &[]).await;
    assert_eq!(r.code, 1, "{r:?}");
    assert!(
        r.stderr.contains("refusing to read the audit log"),
        "{}",
        r.stderr
    );
    // Group- or world-writable.
    cfg.audit_owner_uid = my_uid();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&cfg.audit_log, std::fs::Permissions::from_mode(0o666)).unwrap();
    let r = cli(&cfg, &["logs", "--audit"], &[], &[]).await;
    assert_eq!(r.code, 1, "{r:?}");
    assert!(!r.stdout.contains("forged"));
}

#[tokio::test]
async fn logs_follow_streams_the_journal_and_new_audit_lines() {
    let w = World::start().await;
    let data = w.dir.path().join("journal.txt");
    std::fs::write(&data, "journal-line-1\njournal-line-2\n").unwrap();
    let mut cfg = w.cfg.clone();
    // Prints two lines, waits a moment (so that the audit append below lands while following),
    // then ends: `--follow` ends with journalctl.
    cfg.journalctl = write_script(
        w.dir.path(),
        "journalctl-follow",
        &format!("cat '{}'\nsleep 1\n", data.display()),
    );
    write_audit(&cfg.audit_log, "audit-old-1\n");
    let audit = cfg.audit_log.clone();
    let appender = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&audit)
            .unwrap();
        f.write_all(b"audit-new-2\n").unwrap();
    });
    let r = cli(&cfg, &["logs", "--follow", "-n", "5"], &[], &[]).await;
    appender.await.unwrap();
    assert_eq!(r.code, 0, "{r:?}");
    for needle in [
        "journal| journal-line-1",
        "journal| journal-line-2",
        "audit  | audit-old-1",
        "audit  | audit-new-2",
    ] {
        assert!(
            r.stdout.contains(needle),
            "{needle:?} missing from {}",
            r.stdout
        );
    }
}

// ----------------------------------------------------------------------------------- root only

#[tokio::test]
async fn every_command_refuses_a_non_root_caller_before_touching_a_daemon() {
    let w = World::start().await;
    // The stand-ins would record any connection; the real sockets would answer.
    let before = w.privd_admin.commands().len();
    for args in [
        vec!["status"],
        vec!["devices", "list"],
        vec!["devices", "revoke", "abcd"],
        vec!["pairing", "code"],
        vec!["pairing", "token"],
        vec!["pin", "set"],
        vec!["pin", "reset-lockout", "--yes"],
        vec!["setup", "begin"],
        vec!["desktop", "stop"],
        vec!["docker", "enable", "--yes"],
        vec!["snapshots", "list"],
        vec!["logs"],
        vec!["update", "check"],
        vec!["uninstall", "--keep-desktop", "--yes"],
    ] {
        let r = cli_as(&w.cfg, 1000, &args, &[], &[]).await;
        assert_eq!(r.code, 7, "{args:?}: {r:?}");
        assert!(
            r.stderr.contains("must run as root"),
            "{args:?}: {}",
            r.stderr
        );
        assert!(r.stdout.is_empty());
        assert!(
            r.asked.is_empty(),
            "no question is asked of a non-root caller"
        );
    }
    let j = cli_as(&w.cfg, 1000, &["status", "--json"], &[], &[]).await;
    assert_eq!(j.code, 7);
    assert_eq!(j.json()["error"]["code"], "NOT_ROOT");
    assert_eq!(
        w.privd_admin.commands().len(),
        before,
        "no request reached privd"
    );
    // Help and the version need no privilege.
    for args in [
        vec!["help"],
        vec!["--help"],
        vec!["--version"],
        vec!["devices", "--help"],
    ] {
        let r = cli_as(&w.cfg, 1000, &args, &[], &[]).await;
        assert_eq!(r.code, 0, "{args:?}: {r:?}");
        assert!(!r.stdout.is_empty());
    }
}
