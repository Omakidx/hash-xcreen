//! "Check the current password, then set the new one" (ipc.md 6.9): the secret only in the 0600
//! file, only the helper's exit status trusted, and the whole sequence shielded against cancel.

mod common;

use std::time::Duration;

use common::{Fake, Recorded};
use hx_provision::password::{CurrentPassword, PasswordChange, change_user_password};
use hx_provision::session::PASSWORD_CHECK_HELPER;
use hx_provision::{ProvisionError, Secrets, Username};

const OLD: &str = "old-pass-with-spaces 1!";
const NEW: &str = "new-pass-different 2?";

fn user() -> Username {
    Username::new("alice").unwrap()
}

fn secrets() -> Secrets {
    Secrets::none()
        .with_user_password(NEW)
        .unwrap()
        .with_current_password(OLD)
        .unwrap()
}

async fn fake_with_running_c1() -> Fake {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("c1".into(), "Running".into());
    });
    fake
}

fn execs(log: &[Recorded]) -> Vec<String> {
    log.iter()
        .filter(|r| r.path.ends_with("/exec"))
        .map(|r| r.json()["command"].to_string())
        .collect()
}

fn carrying<'a>(log: &'a [Recorded], secret: &str) -> Vec<&'a Recorded> {
    log.iter()
        .filter(|r| String::from_utf8_lossy(&r.body).contains(secret))
        .collect()
}

#[tokio::test]
async fn right_current_password_sets_the_new_one() {
    let fake = fake_with_running_c1().await;
    fake.rule(PASSWORD_CHECK_HELPER, 0, "", "");
    let out = change_user_password(&fake.client(), "c1", &user(), secrets(), true)
        .await
        .unwrap();
    assert_eq!(out, PasswordChange::Changed);

    let log = fake.log();
    let cmds = execs(&log);
    let check = cmds.iter().position(|c| c.contains("hx-pwcheck")).unwrap();
    let set = cmds.iter().position(|c| c.contains("chpasswd")).unwrap();
    assert!(check < set, "the check runs first");
    // Fixed argv: helper and the login name, nothing else.
    assert!(
        cmds[check].contains(&format!(
            "\"timeout\",\"--kill-after=15\",\"30\",\"{PASSWORD_CHECK_HELPER}\",\"alice\"]"
        )),
        "{}",
        cmds[check]
    );

    // Each secret is in exactly one request body: its own 0600 file in the 0700 directory.
    for (secret, expect_body) in [(OLD, OLD.to_string()), (NEW, format!("alice:{NEW}\n"))] {
        let c = carrying(&log, secret);
        assert_eq!(
            c.len(),
            1,
            "{secret}: {:?}",
            c.iter().map(|r| r.key()).collect::<Vec<_>>()
        );
        assert!(
            c[0].path.contains("path=/run/hx-provision/stdin-"),
            "{}",
            c[0].path
        );
        assert_eq!(c[0].headers["x-incus-mode"], "0600");
        assert_eq!(c[0].body, expect_body.into_bytes());
    }
    // Never in a URL, a header or an exec command.
    for r in &log {
        for secret in [OLD, NEW, "pass-with", "different"] {
            assert!(!r.path.contains(secret) && r.headers.values().all(|v| !v.contains(secret)));
            if r.path.ends_with("/exec") {
                assert!(!String::from_utf8_lossy(&r.body).contains(secret));
            }
        }
    }
    // Swept before and after, and no secret file is left.
    let sweeps: Vec<_> = cmds.iter().filter(|c| c.contains("-delete")).collect();
    assert!(sweeps.len() >= 2);
    assert!(cmds.last().unwrap().contains("-delete"));
    assert!(fake.with(|s| s.files.keys().all(|k| !k.contains("/stdin-"))));
}

#[tokio::test]
async fn wrong_current_password_changes_nothing() {
    let fake = fake_with_running_c1().await;
    fake.rule(PASSWORD_CHECK_HELPER, 1, "looks fine to me", "");
    let out = change_user_password(&fake.client(), "c1", &user(), secrets(), true)
        .await
        .unwrap();
    assert_eq!(out, PasswordChange::CurrentPasswordWrong);
    let log = fake.log();
    assert!(execs(&log).iter().all(|c| !c.contains("chpasswd")));
    assert!(
        carrying(&log, NEW).is_empty(),
        "the new password is never even written"
    );
    assert!(fake.with(|s| s.files.keys().all(|k| !k.contains("/stdin-"))));
    assert!(execs(&log).last().unwrap().contains("-delete"), "swept");
}

#[tokio::test]
async fn only_the_exit_status_counts_not_the_output() {
    // The helper prints a success-looking message but exits 1: not accepted.
    let fake = fake_with_running_c1().await;
    fake.rule(PASSWORD_CHECK_HELPER, 1, "OK match\n", "OK");
    assert_eq!(
        change_user_password(&fake.client(), "c1", &user(), secrets(), true)
            .await
            .unwrap(),
        PasswordChange::CurrentPasswordWrong
    );
    // The helper prints a failure-looking message but exits 0: accepted.
    let fake = fake_with_running_c1().await;
    fake.rule(PASSWORD_CHECK_HELPER, 0, "mismatch\n", "wrong password");
    assert_eq!(
        change_user_password(&fake.client(), "c1", &user(), secrets(), true)
            .await
            .unwrap(),
        PasswordChange::Changed
    );
}

#[tokio::test]
async fn an_unavailable_helper_fails_closed() {
    for code in [127, 2, 3, 126, 255] {
        let fake = fake_with_running_c1().await;
        fake.rule(PASSWORD_CHECK_HELPER, code, "", "not found");
        let out = change_user_password(&fake.client(), "c1", &user(), secrets(), true)
            .await
            .unwrap();
        assert_eq!(
            out,
            PasswordChange::CheckUnavailable {
                exit_code: code as i32
            }
        );
        assert!(execs(&fake.log()).iter().all(|c| !c.contains("chpasswd")));
    }
}

#[tokio::test]
async fn a_helper_binary_that_does_not_exist_fails_closed() {
    // A real Incus refuses to start a missing command with `400 Command not found`.
    let fake = fake_with_running_c1().await;
    fake.with(|s| {
        s.overrides.insert(
            "POST /1.0/instances/c1/exec".into(),
            (
                400,
                r#"{"type":"error","error_code":400,"error":"Command not found"}"#.into(),
            ),
        );
    });
    let out = change_user_password(&fake.client(), "c1", &user(), secrets(), true)
        .await
        .unwrap();
    assert_eq!(out, PasswordChange::CheckUnavailable { exit_code: 127 });
    assert!(fake.with(|s| s.files.keys().all(|k| !k.contains("/stdin-"))));
}

#[tokio::test]
async fn without_require_current_there_is_no_check() {
    let fake = fake_with_running_c1().await;
    let new_only = Secrets::none().with_user_password(NEW).unwrap();
    let out = change_user_password(&fake.client(), "c1", &user(), new_only, false)
        .await
        .unwrap();
    assert_eq!(out, PasswordChange::Changed);
    assert!(execs(&fake.log()).iter().all(|c| !c.contains("hx-pwcheck")));
}

#[tokio::test]
async fn a_required_but_missing_current_password_is_an_error_not_a_skipped_check() {
    let fake = fake_with_running_c1().await;
    let new_only = Secrets::none().with_user_password(NEW).unwrap();
    let err = change_user_password(&fake.client(), "c1", &user(), new_only, true)
        .await
        .unwrap_err();
    assert!(matches!(err, ProvisionError::Apply(_)), "{err}");
    assert!(execs(&fake.log()).iter().all(|c| !c.contains("chpasswd")));
}

#[tokio::test]
async fn a_missing_new_password_is_an_error() {
    let fake = fake_with_running_c1().await;
    fake.rule(PASSWORD_CHECK_HELPER, 0, "", "");
    let cur_only = Secrets::none().with_current_password(OLD).unwrap();
    let err = change_user_password(&fake.client(), "c1", &user(), cur_only, true)
        .await
        .unwrap_err();
    assert!(matches!(err, ProvisionError::Apply(_)), "{err}");
    assert!(fake.with(|s| s.files.keys().all(|k| !k.contains("/stdin-"))));
}

#[tokio::test]
async fn a_stopped_or_unknown_desktop_is_refused_before_any_secret_is_written() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.instances.insert("c1".into(), "Stopped".into());
    });
    let err = change_user_password(&fake.client(), "c1", &user(), secrets(), true)
        .await
        .unwrap_err();
    assert!(matches!(err, ProvisionError::NotRunning), "{err}");
    let err = change_user_password(&fake.client(), "nope", &user(), secrets(), true)
        .await
        .unwrap_err();
    assert!(matches!(err, ProvisionError::Incus(_)), "{err}");
    assert!(fake.log().iter().all(|r| !r.path.contains("/files")));
}

#[tokio::test]
async fn chpasswd_failure_is_an_error_and_still_sweeps() {
    let fake = fake_with_running_c1().await;
    fake.rule(PASSWORD_CHECK_HELPER, 0, "", "");
    fake.rule("chpasswd", 1, "", "chpasswd: boom");
    let err = change_user_password(&fake.client(), "c1", &user(), secrets(), true)
        .await
        .unwrap_err();
    assert!(matches!(err, ProvisionError::Apply(_)), "{err}");
    assert!(!err.to_string().contains(NEW) && !err.to_string().contains(OLD));
    assert!(execs(&fake.log()).last().unwrap().contains("-delete"));
    assert!(fake.with(|s| s.files.keys().all(|k| !k.contains("/stdin-"))));
}

#[tokio::test]
async fn a_failing_secret_command_never_puts_its_output_in_the_error() {
    // A tool that echoes what it was given must not carry the password into an error message.
    let fake = fake_with_running_c1().await;
    fake.rule(PASSWORD_CHECK_HELPER, 0, "", "");
    fake.rule("chpasswd", 1, NEW, &format!("bad line: alice:{NEW}"));
    let err = change_user_password(&fake.client(), "c1", &user(), secrets(), true)
        .await
        .unwrap_err();
    let shown = format!("{err} {err:?}");
    assert!(
        !shown.contains(NEW) && !shown.contains("different"),
        "{shown}"
    );
    assert!(shown.contains("withheld"), "{shown}");

    // The same through the post stage's runner.
    let fake = Fake::start().await;
    fake.rule("chpasswd", 1, NEW, &format!("bad line: alice:{NEW}"));
    let plan = hx_provision::Catalog::embedded()
        .resolve(
            hx_provision::RecipeId {
                distro: hx_provision::Distro::Debian13,
                desktop: hx_provision::Desktop::Xfce,
                preset: hx_provision::Preset::Basic,
            },
            &[],
        )
        .unwrap();
    let client = fake.client();
    let exec = hx_provision::IncusExecutor::new(&client, "c1");
    let secrets = Secrets::none().with_user_password(NEW).unwrap();
    let err = hx_provision::apply_stage(
        &exec,
        &plan,
        hx_provision::Stage::Post,
        &secrets,
        &mut |_| {},
    )
    .await
    .unwrap_err();
    let shown = format!("{err} {err:?}");
    assert!(
        !shown.contains(NEW) && !shown.contains("different"),
        "{shown}"
    );
}

#[tokio::test]
async fn standalone_check_reports_the_three_outcomes() {
    use hx_provision::password::check_user_password;
    for (code, want) in [
        (0, CurrentPassword::Matches),
        (1, CurrentPassword::Wrong),
        (9, CurrentPassword::Unavailable { exit_code: 9 }),
    ] {
        let fake = fake_with_running_c1().await;
        fake.rule(PASSWORD_CHECK_HELPER, code, "", "");
        let got = check_user_password(&fake.client(), "c1", &user(), secrets())
            .await
            .unwrap();
        assert_eq!(got, want);
        assert!(execs(&fake.log()).iter().all(|c| !c.contains("chpasswd")));
    }
}

/// The shielded task's operations belong to the task, not to the request's client: a
/// `cancel_in_flight` on the caller's client sees none of them and cannot cancel a secret path.
#[tokio::test]
async fn the_callers_client_does_not_see_the_shielded_operations() {
    let fake = fake_with_running_c1().await;
    fake.rule(PASSWORD_CHECK_HELPER, 0, "", "");
    fake.with(|s| s.stuck_ops = true); // the task's first exec stays pending
    let client = fake.client().scoped();
    let c2 = client.clone();
    let task =
        tokio::spawn(
            async move { change_user_password(&c2, "c1", &user(), secrets(), true).await },
        );
    for _ in 0..300 {
        if fake.log().iter().any(|r| r.path.ends_with("/exec")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        fake.log().iter().any(|r| r.path.ends_with("/exec")),
        "exec is pending"
    );
    assert!(client.in_flight_operations().is_empty());
    assert_eq!(client.cancel_in_flight(Duration::from_secs(1)).await, Ok(0));
    assert!(
        fake.log()
            .iter()
            .all(|r| r.method != "DELETE" || !r.path.contains("/operations/")),
        "no operation of the secret path was cancelled"
    );
    // Let it finish.
    fake.with(|s| s.stuck_ops = false);
    assert_eq!(task.await.unwrap().unwrap(), PasswordChange::Changed);
}

/// The point of the shield: the caller drops the future in the middle (here: while the check is
/// running at the daemon); the sequence still runs to its end and sweeps.
#[tokio::test]
async fn dropping_the_future_mid_flight_still_finishes_and_sweeps() {
    let fake = fake_with_running_c1().await;
    fake.rule(PASSWORD_CHECK_HELPER, 0, "", "");
    // Operations do not complete while this is set: the first exec (the pre-sweep) hangs.
    fake.with(|s| s.stuck_ops = true);
    let client = fake.client().scoped();
    let c2 = client.clone();
    let task =
        tokio::spawn(
            async move { change_user_password(&c2, "c1", &user(), secrets(), true).await },
        );
    for _ in 0..300 {
        if fake.log().iter().any(|r| r.path.ends_with("/exec")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(fake.log().iter().any(|r| r.path.ends_with("/exec")));
    // Cancel: drop the caller's future.
    task.abort();
    let _ = task.await;
    // Let the daemon finish its operations; nobody is waiting for the result any more.
    fake.with(|s| s.stuck_ops = false);
    let mut done = false;
    for _ in 0..500 {
        let cmds = execs(&fake.log());
        if cmds.iter().filter(|c| c.contains("-delete")).count() >= 2
            && cmds.iter().any(|c| c.contains("chpasswd"))
        {
            done = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        done,
        "the detached task did not finish: {:?}",
        execs(&fake.log())
    );
    assert!(fake.with(|s| s.files.keys().all(|k| !k.contains("/stdin-"))));
    assert!(execs(&fake.log()).last().unwrap().contains("-delete"));
}
