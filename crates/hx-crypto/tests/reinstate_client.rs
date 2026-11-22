//! The reinstate client (`INTENT_REINSTATE`, protocol §11.7) against the real `Authenticator`
//! with a fake password gate.

mod common;

use std::time::Duration;

use common::{Env, PREF, PwGate, config};
use hx_crypto::{
    Error, Outcome, PasswordVerdict, RevokedBy,
    reinstate_client::{
        MAX_ATTEMPTS, ReinstateConnect, ReinstateOptions, ReinstateOutcome, connect_reinstate,
        reinstate,
    },
    setup::Password,
};
use hx_proto::version::ProtocolVersion;

const GOOD: &str = "correct horse battery staple";

fn opts(e: &Env) -> ReinstateOptions {
    ReinstateOptions {
        confirmed_server_version: Some(e.paired_version),
        preference: PREF,
        device_name: "laptop".into(),
        ..Default::default()
    }
}

fn pw(s: &str) -> Password {
    Password::new(s).expect("password")
}

async fn run(e: &Env, p: &Password) -> hx_crypto::Result<ReinstateOutcome> {
    reinstate(&e.target(), &e.device, e.server_key.public(), p, &opts(e)).await
}

#[tokio::test]
async fn a_locked_out_device_is_reinstated_and_the_password_reaches_the_gate_unchanged() {
    let mut e = Env::new(config()).await;
    let gate = PwGate::new(&[], PasswordVerdict::Right);
    e.auth.set_reinstate_gate(gate.clone());
    e.lock_out();
    assert!(e.registry_record().is_revoked());

    assert_eq!(
        run(&e, &pw(GOOD)).await.expect("outcome"),
        ReinstateOutcome::Reinstated
    );
    let Outcome::Reinstated { device } = e.next().await.expect("outcome") else {
        panic!("expected Reinstated");
    };
    assert!(!device.is_revoked());
    assert_eq!(gate.seen.lock().unwrap().as_slice(), [GOOD.as_bytes()]);
    assert!(!e.registry_record().is_revoked());
}

#[tokio::test]
async fn a_wrong_password_reports_the_attempts_left_and_the_device_stays_revoked() {
    let mut e = Env::new(config()).await;
    e.auth
        .set_reinstate_gate(PwGate::new(&[], PasswordVerdict::Wrong));
    e.lock_out();
    let out = run(&e, &pw("not it")).await.expect("outcome");
    // The budget is 3 per hour; one was used.
    assert_eq!(out, ReinstateOutcome::WrongPassword { attempts_left: 2 });
    assert!(
        e.next().await.is_err(),
        "the exchange ended without a success"
    );
    assert!(e.registry_record().is_revoked());
}

#[tokio::test]
async fn at_most_three_attempts_go_out_on_one_connection_and_the_budget_ends_in_backoff() {
    let mut e = Env::new(config()).await;
    e.auth
        .set_reinstate_gate(PwGate::new(&[], PasswordVerdict::Wrong));
    e.lock_out();
    let ReinstateConnect::Ready(mut a) =
        connect_reinstate(&e.target(), &e.device, e.server_key.public(), &opts(&e))
            .await
            .expect("connects")
    else {
        panic!("expected Ready");
    };
    assert_eq!(a.attempts_left(), 3);
    for left in [2, 1, 0] {
        assert_eq!(
            a.submit(&pw("nope")).await.expect("reply"),
            ReinstateOutcome::WrongPassword {
                attempts_left: left
            }
        );
    }
    assert_eq!(MAX_ATTEMPTS, 3);
    let fourth = a.submit(&pw("nope")).await;
    assert!(matches!(fourth, Err(Error::Protocol(_))), "{fourth:?}");
    a.abandon().await;
    let _ = e.next().await;

    // A new connection: the per-device hourly budget is spent, so it is answered BACKOFF
    // without a check.
    let out = run(&e, &pw("nope")).await.expect("outcome");
    let ReinstateOutcome::Backoff { retry_after } = out else {
        panic!("expected Backoff, got {out:?}");
    };
    assert!(retry_after > Duration::ZERO && retry_after <= Duration::from_secs(3600));
    // An hour later the budget is back.
    e.clock.advance(Duration::from_secs(3601));
    assert!(matches!(
        run(&e, &pw("nope")).await,
        Ok(ReinstateOutcome::WrongPassword { .. })
    ));
}

#[tokio::test]
async fn a_verifier_that_cannot_answer_is_not_available_and_ends_the_exchange() {
    let e = Env::new(config()).await;
    e.auth
        .set_reinstate_gate(PwGate::new(&[], PasswordVerdict::Unavailable));
    e.lock_out();
    let out = run(&e, &pw(GOOD)).await.expect("outcome");
    assert!(
        matches!(out, ReinstateOutcome::NotAvailable { .. }),
        "{out:?}"
    );
    assert!(e.registry_record().is_revoked());
}

#[tokio::test]
async fn no_password_verifier_on_the_server_is_not_available() {
    let e = Env::new(config()).await;
    e.auth.set_reinstate_gate(PwGate::without_password());
    e.lock_out();
    let out = run(&e, &pw(GOOD)).await.expect("outcome");
    assert!(
        matches!(out, ReinstateOutcome::NotAvailable { .. }),
        "{out:?}"
    );
}

#[tokio::test]
async fn a_device_that_does_not_qualify_is_refused_uniformly() {
    // Active, revoked by someone else, and too old: all the same answer, and no check.
    let gate = PwGate::new(&[], PasswordVerdict::Right);

    let e = Env::new(config()).await;
    e.auth.set_reinstate_gate(gate.clone());
    assert_eq!(
        run(&e, &pw(GOOD)).await.expect("active"),
        ReinstateOutcome::Refused
    );

    let e = Env::new(config()).await;
    e.auth.set_reinstate_gate(gate.clone());
    e.revoke(RevokedBy::Operator);
    assert_eq!(
        run(&e, &pw(GOOD)).await.expect("operator"),
        ReinstateOutcome::Refused
    );

    let mut e = Env::new(config()).await;
    e.auth.set_reinstate_gate(gate.clone());
    e.lock_out();
    e.clock.advance(Duration::from_secs(31 * 86_400));
    assert_eq!(
        run(&e, &pw(GOOD)).await.expect("too old"),
        ReinstateOutcome::Refused
    );
    assert!(
        gate.seen.lock().unwrap().is_empty(),
        "no password was checked"
    );
    let _ = &mut e;
}

#[tokio::test]
async fn an_unconfirmed_or_old_server_means_update_required_and_nothing_connects() {
    let mut e = Env::new(config()).await;
    e.auth
        .set_reinstate_gate(PwGate::new(&[], PasswordVerdict::Right));
    e.lock_out();
    for v in [
        None,
        Some(ProtocolVersion { major: 1, minor: 2 }),
        Some(ProtocolVersion { major: 2, minor: 3 }),
    ] {
        let mut o = opts(&e);
        o.confirmed_server_version = v;
        let r = reinstate(&e.target(), &e.device, e.server_key.public(), &pw(GOOD), &o).await;
        assert!(matches!(r, Err(Error::UpdateRequired)), "{v:?}: {r:?}");
    }
    assert!(e.no_outcome());
}

#[test]
fn nothing_secret_reaches_debug_or_errors() {
    let p = pw("hunter2-secret");
    assert_eq!(format!("{p:?}"), "Password([redacted])");
    let err = Password::new("bad\npassword hunter2").expect_err("rejected");
    assert!(!format!("{err} {err:?}").contains("hunter2"));
    let outcome = ReinstateOutcome::WrongPassword { attempts_left: 1 };
    assert!(!format!("{outcome:?}").contains("hunter2"));
}
