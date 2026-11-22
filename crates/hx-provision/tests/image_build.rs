//! The image path (`build_image`, `seal_image`, `verify_sealed`) and the restart that ends
//! `finish_prebuilt`, against the fake daemon.

mod common;

use common::{Fake, Recorded};
use hx_provision::incus::ImageSource;
use hx_provision::orchestrate::{
    DesktopSpec, Limits, ProvisionError, build_image, finish_prebuilt, seal_image, verify_sealed,
};
use hx_provision::{MemSource, Naming, Secrets};

const NAME: &str = "hx1d-img-t1";

fn plan() -> hx_provision::Plan {
    let src = MemSource::new().with(
        "r.toml",
        "[recipe]\nname=\"tiny\"\nbase_image=\"images:debian/13\"\n[vars]\ndistro=\"debian\"\ndistro_version=\"13\"\n[user]\nname=\"desk\"\nuid=1000\n[apt]\npackages=[\"curl\"]\n",
    );
    hx_provision::recipe::resolve(&src, "r.toml", &[]).unwrap()
}

fn spec(plan: &hx_provision::Plan) -> DesktopSpec {
    DesktopSpec::for_plan(
        NAME,
        Naming::with_prefix("hx1d-img-").unwrap(),
        plan,
        Limits::default(),
    )
}

fn state_actions(log: &[Recorded]) -> Vec<String> {
    log.iter()
        .filter(|r| r.key() == format!("PUT /1.0/instances/{NAME}/state"))
        .map(|r| r.json()["action"].as_str().unwrap_or("").to_string())
        .collect()
}

fn exec_bodies(log: &[Recorded]) -> Vec<String> {
    log.iter()
        .filter(|r| r.path.ends_with("/exec"))
        .map(|r| r.json().to_string())
        .collect()
}

#[tokio::test]
async fn finish_prebuilt_restarts_and_waits_for_running_after_the_post_stage() {
    let fake = Fake::start().await;
    let p = plan();
    let local = spec(&p).with_image(ImageSource::LocalFingerprint("a".repeat(64)));
    let secrets = Secrets::none().with_user_password("Tr0ub4dor&3-x").unwrap();
    finish_prebuilt(&fake.client(), &p, &local, &secrets, &mut |_| {})
        .await
        .unwrap();
    let log = fake.log();
    assert_eq!(state_actions(&log), ["start", "restart"]);
    let restart_at = log
        .iter()
        .position(|r| r.json().to_string().contains("\"restart\""))
        .unwrap();
    let is_poll = |r: &Recorded| {
        r.path.ends_with("/exec") && r.json().to_string().contains("is-system-running")
    };
    let last_step = log
        .iter()
        .rposition(|r| r.path.ends_with("/exec") && !is_poll(r))
        .unwrap();
    assert!(last_step < restart_at, "post stage first, then the restart");
    assert!(
        log[restart_at..].iter().any(is_poll),
        "running is awaited after the restart"
    );
}

#[tokio::test]
async fn build_image_builds_seals_stops_and_verifies_without_a_post_stage() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.files.insert("/etc/machine-id".into(), Vec::new());
    });
    let p = plan();
    let report = build_image(&fake.client(), &p, &spec(&p), &mut |_| {})
        .await
        .unwrap();
    assert!(
        !report.timings.is_empty(),
        "the build stage reported its steps"
    );
    let log = fake.log();
    // start, then a graceful stop; never a restart.
    assert_eq!(state_actions(&log), ["start", "stop"]);
    let stop = log
        .iter()
        .find(|r| r.json()["action"] == "stop")
        .unwrap()
        .json();
    assert_eq!(stop["force"], false, "graceful stop");
    let bodies = exec_bodies(&log);
    let all = bodies.join("\n");
    assert!(all.contains("--no-install-recommends"), "build stage ran");
    assert!(!all.contains("chpasswd"), "no post stage, no password");
    assert!(!all.contains("apt_run 3600 upgrade"), "no security updates");
    // The seal ran after the build and before the stop.
    let seal_at = log
        .iter()
        .position(|r| r.json().to_string().contains("machine-id"))
        .unwrap();
    let stop_at = log
        .iter()
        .position(|r| r.json()["action"] == "stop")
        .unwrap();
    let last_build_exec = log
        .iter()
        .rposition(|r| r.json().to_string().contains("--no-install-recommends"))
        .unwrap();
    assert!(last_build_exec < seal_at && seal_at < stop_at);
    // verify_sealed read the file after the stop.
    let read_at = log
        .iter()
        .rposition(|r| r.method == "GET" && r.path.contains("/files?path=/etc/machine-id"))
        .unwrap();
    assert!(read_at > stop_at);
    // The container is left (stopped) for `incus publish`.
    assert_eq!(fake.with(|s| s.instances[NAME].clone()), "Stopped");
}

#[tokio::test]
async fn build_image_fails_when_the_machine_id_survives_the_seal() {
    let fake = Fake::start().await;
    fake.with(|s| {
        s.files
            .insert("/etc/machine-id".into(), b"0123456789abcdef\n".to_vec());
    });
    let p = plan();
    let e = build_image(&fake.client(), &p, &spec(&p), &mut |_| {})
        .await
        .unwrap_err();
    assert!(
        matches!(&e, ProvisionError::Invalid(m) if m.contains("not sealed")),
        "{e:?}"
    );
}

#[tokio::test]
async fn verify_sealed_wants_an_empty_file_not_a_missing_one() {
    let fake = Fake::start().await;
    let c = fake.client();
    let missing = verify_sealed(&c, NAME).await.unwrap_err();
    assert!(
        matches!(&missing, ProvisionError::Invalid(m) if m.contains("missing")),
        "{missing:?}"
    );
    fake.with(|s| {
        s.files.insert("/etc/machine-id".into(), Vec::new());
    });
    verify_sealed(&c, NAME).await.unwrap();
    fake.with(|s| {
        s.files
            .insert("/etc/machine-id".into(), b"uninitialized\n".to_vec());
    });
    assert!(verify_sealed(&c, NAME).await.is_err());
    // A non-regular file (a symlink or directory planted in the image) is not "sealed" either.
    fake.with(|s| {
        s.files.insert("/etc/machine-id".into(), Vec::new());
        s.file_types
            .insert("/etc/machine-id".into(), "symlink".into());
    });
    assert!(verify_sealed(&c, NAME).await.is_err());
}

#[tokio::test]
async fn the_seal_script_truncates_the_machine_id_and_clears_what_must_not_be_shared() {
    let fake = Fake::start().await;
    seal_image(&fake.client(), NAME, "desk").await.unwrap();
    let log = fake.log();
    let exec = log
        .iter()
        .find(|r| r.path.ends_with("/exec") && r.json().to_string().contains("machine-id"))
        .unwrap()
        .json();
    let cmd: Vec<String> = exec["command"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    // The wrapper's argv: sh -c CAPTURE sh base stdin timeout --kill-after=15 N <argv...>
    let at = cmd.iter().position(|a| a == "bash").unwrap();
    assert_eq!(&cmd[at..at + 2], ["bash", "-c"]);
    assert_eq!(cmd[at + 3], "bash");
    assert_eq!(
        cmd[at + 4],
        "desk",
        "the user is an argument, not interpolated"
    );
    let script = &cmd[at + 2];
    assert!(
        script.contains(": > /etc/machine-id"),
        "truncated, not removed"
    );
    assert!(!script.contains("rm -f /etc/machine-id"));
    assert!(
        !script.contains("uninitialized"),
        "empty, so first-boot presets do not run"
    );
    assert!(
        script.contains("[ -f /var/lib/dbus/machine-id ] && [ ! -L /var/lib/dbus/machine-id ]"),
        "the dbus id is removed only when it is a regular file"
    );
    for needle in [
        "/var/lib/systemd/random-seed",
        "/var/lib/systemd/credential.secret",
        "/var/log/journal",
        "find /var/log -type f -delete",
        "/etc/ssh/ssh_host_*",
        "/tmp /var/tmp",
        "/root/.bash_history",
        "$h/.bash_history",
        "$h/.cache",
        "/var/lib/apt/lists/*",
    ] {
        assert!(script.contains(needle), "{needle}");
    }
}

#[tokio::test]
async fn seal_refuses_a_bad_user_and_reports_a_failing_script() {
    let fake = Fake::start().await;
    for bad in ["", "a b", "x;rm -rf /", "../root", "Root", "root"] {
        let e = seal_image(&fake.client(), NAME, bad).await.unwrap_err();
        assert!(matches!(e, ProvisionError::Invalid(_)), "{bad}: {e:?}");
    }
    assert!(fake.log().is_empty(), "nothing reached the container");
    fake.rule(
        "machine-id",
        1,
        "",
        "find: cannot delete\n\x1b[31mred\x1b[0m",
    );
    let e = seal_image(&fake.client(), NAME, "desk").await.unwrap_err();
    let ProvisionError::Invalid(m) = &e else {
        panic!("{e:?}")
    };
    assert!(m.contains("exit 1") && m.contains("cannot delete"), "{m}");
    assert!(!m.contains('\x1b'), "container text is sanitized");
}
