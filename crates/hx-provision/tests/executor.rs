//! The stage runner and command lowering, against a recording executor.

use std::sync::Mutex;

use hx_provision::lower::lower;
use hx_provision::{
    Action, Addon, ApplyError, Catalog, Desktop, Distro, ExecError, ExecOutput, ExecRequest,
    Executor, FilePush, Preset, Progress, RecipeId, Secret, Secrets, Stage, Step, StepFailure,
    apply_stage,
};

const PASSWORD: &str = "correct horse battery staple 9!";

#[derive(Default)]
struct Recorder {
    log: Mutex<Vec<Action>>,
    /// Labels whose command should fail with this exit code.
    fail: Vec<(String, i32)>,
}

impl Executor for Recorder {
    async fn exec(&self, request: &ExecRequest) -> Result<ExecOutput, ExecError> {
        // `ExecRequest` is deliberately not `Clone`: rebuild it, copying the secret explicitly.
        let copy = ExecRequest {
            label: request.label.clone(),
            argv: request.argv.clone(),
            env: request.env.clone(),
            cwd: request.cwd.clone(),
            stdin: request
                .stdin
                .as_ref()
                .map(|s| Secret::from_slice(s.expose())),
            timeout: request.timeout,
        };
        self.log.lock().unwrap().push(Action::Exec(copy));
        let code = self
            .fail
            .iter()
            .find(|(l, _)| request.label.contains(l.as_str()))
            .map(|(_, c)| *c)
            .unwrap_or(0);
        Ok(ExecOutput {
            exit_code: code,
            stdout: String::new(),
            stderr: if code == 0 {
                String::new()
            } else {
                "boom on stderr".into()
            },
        })
    }

    async fn push_file(&self, file: &FilePush) -> Result<(), ExecError> {
        self.log.lock().unwrap().push(Action::Push(file.clone()));
        Ok(())
    }
}

fn plan(addons: &[Addon], preset: Preset) -> hx_provision::Plan {
    Catalog::embedded()
        .resolve(
            RecipeId {
                distro: Distro::Debian13,
                desktop: Desktop::Xfce,
                preset,
            },
            addons,
        )
        .unwrap()
}

fn secrets() -> Secrets {
    Secrets::none().with_user_password(PASSWORD).unwrap()
}

fn contains_password(a: &Action) -> bool {
    match a {
        Action::Exec(r) => {
            let mut hay = format!("{} {:?} {:?} {:?}", r.label, r.argv, r.env, r.cwd);
            hay.push_str(&format!("{r:?}"));
            hay.contains(PASSWORD) || hay.contains("battery")
        }
        Action::Push(f) => String::from_utf8_lossy(&f.content).contains(PASSWORD),
    }
}

#[tokio::test]
async fn post_stage_passes_the_password_on_stdin_only() {
    let p = plan(&[], Preset::Developer);
    let rec = Recorder::default();
    let mut events = Vec::new();
    let report = apply_stage(&rec, &p, Stage::Post, &secrets(), &mut |e| {
        events.push(format!("{e:?}"))
    })
    .await
    .unwrap();
    assert!(report.warnings.is_empty());
    let log = rec.log.lock().unwrap();
    // Exactly one request carries stdin, and it is chpasswd with `user:password\n`.
    let with_stdin: Vec<&ExecRequest> = log
        .iter()
        .filter_map(|a| match a {
            Action::Exec(r) if r.stdin.is_some() => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(with_stdin.len(), 1);
    assert_eq!(with_stdin[0].argv, ["chpasswd"]);
    assert_eq!(
        with_stdin[0].stdin.as_ref().unwrap().expose(),
        format!("desk:{PASSWORD}\n").as_bytes()
    );
    // The password is nowhere else: not in argv, env, labels, Debug output, pushed files, progress.
    for a in log.iter() {
        assert!(!contains_password(a), "{a:?}");
    }
    for e in &events {
        assert!(!e.contains(PASSWORD) && !e.contains("battery"), "{e}");
    }
    let dbg = format!("{:?}", with_stdin[0]);
    assert!(
        dbg.contains("<") && dbg.contains("bytes>") && !dbg.contains("desk:"),
        "{dbg}"
    );
    let sdbg = format!("{:?}", secrets());
    assert!(
        sdbg.contains("redacted") && !sdbg.contains("battery"),
        "{sdbg}"
    );
}

#[tokio::test]
async fn build_stage_never_touches_the_password() {
    let p = plan(&[Addon::Docker], Preset::Basic);
    let rec = Recorder::default();
    apply_stage(&rec, &p, Stage::Build, &secrets(), &mut |_| {})
        .await
        .unwrap();
    for a in rec.log.lock().unwrap().iter() {
        assert!(!contains_password(a));
        if let Action::Exec(r) = a {
            assert!(r.stdin.is_none(), "{r:?}");
        }
    }
}

#[tokio::test]
async fn a_failing_step_reports_no_secret() {
    let p = plan(&[], Preset::Basic);
    let rec = Recorder {
        fail: vec![("set-password".into(), 1)],
        ..Recorder::default()
    };
    let e = apply_stage(&rec, &p, Stage::Post, &secrets(), &mut |_| {})
        .await
        .unwrap_err();
    let msg = e.to_string();
    assert!(
        msg.contains("set-password desk")
            && msg.contains("withheld")
            && !msg.contains("boom on stderr"),
        "{msg}"
    );
    assert!(!msg.contains(PASSWORD) && !format!("{e:?}").contains(PASSWORD));
    assert!(
        matches!(
            e,
            ApplyError::Step {
                stage: Stage::Post,
                index: 3,
                failure: StepFailure::ExitCode { code: 1, .. },
                ..
            }
        ),
        "{e:?}"
    );
}

#[tokio::test]
async fn post_stage_without_a_password_is_refused_before_anything_runs_for_that_step() {
    let p = plan(&[], Preset::Basic);
    let rec = Recorder::default();
    let e = apply_stage(&rec, &p, Stage::Post, &Secrets::none(), &mut |_| {})
        .await
        .unwrap_err();
    assert!(
        matches!(
            e,
            ApplyError::MissingSecret {
                stage: Stage::Post,
                ..
            }
        ),
        "{e:?}"
    );
    // The two earlier steps ran, nothing for set-password did.
    assert!(
        rec.log
            .lock()
            .unwrap()
            .iter()
            .all(|a| !matches!(a, Action::Exec(r) if r.label == "set-password"))
    );
}

#[test]
fn password_validation() {
    assert!(Secrets::none().with_user_password("").is_err());
    assert!(Secrets::none().with_user_password("a\nb").is_err());
    assert!(Secrets::none().with_user_password("a\0b").is_err());
    assert!(Secrets::none().with_user_password("a:b c").is_ok());
}

#[tokio::test]
async fn optional_command_failure_is_a_warning_and_required_failure_stops() {
    let p = plan(&[], Preset::Developer);
    let rec = Recorder {
        fail: vec![("command claude-code".into(), 22)],
        ..Recorder::default()
    };
    let mut events = Vec::new();
    let report = apply_stage(&rec, &p, Stage::Post, &secrets(), &mut |e| {
        events.push(e.clone())
    })
    .await
    .unwrap();
    assert_eq!(report.warnings.len(), 1);
    assert!(
        report.warnings[0].step.contains("claude-code")
            && report.warnings[0].message.contains("22")
    );
    // codex-cli still ran after the failed optional step.
    assert!(
        rec.log
            .lock()
            .unwrap()
            .iter()
            .any(|a| matches!(a, Action::Exec(r) if r.label == "command codex-cli"))
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Progress::Finished { ok: false, .. }))
    );

    let rec = Recorder {
        fail: vec![("apt-install".into(), 100)],
        ..Recorder::default()
    };
    let e = apply_stage(
        &rec,
        &plan(&[], Preset::Basic),
        Stage::Build,
        &Secrets::none(),
        &mut |_| {},
    )
    .await
    .unwrap_err();
    let ApplyError::Step { index, step, .. } = &e else {
        panic!("{e:?}")
    };
    assert!(step.starts_with("apt-install") && *index > 2);
    // Nothing after the failing step ran.
    assert!(
        !rec.log
            .lock()
            .unwrap()
            .iter()
            .any(|a| matches!(a, Action::Exec(r) if r.label.starts_with("ensure-user")))
    );
}

#[tokio::test]
async fn progress_reports_every_step_in_order() {
    let p = plan(&[], Preset::Basic);
    let rec = Recorder::default();
    let mut started = Vec::new();
    apply_stage(&rec, &p, Stage::Build, &Secrets::none(), &mut |e| {
        if let Progress::Started {
            index, total, step, ..
        } = e
        {
            started.push((*index, *total, step.clone()));
        }
    })
    .await
    .unwrap();
    assert_eq!(started.len(), p.build.len());
    assert!(
        started
            .iter()
            .enumerate()
            .all(|(i, (idx, tot, _))| *idx == i + 1 && *tot == p.build.len())
    );
}

fn script_of(a: &Action) -> &str {
    match a {
        Action::Exec(r) => r.argv.last().unwrap(),
        Action::Push(_) => panic!("not an exec"),
    }
}

#[test]
fn every_apt_step_is_bounded_with_timeouts_and_retries() {
    let p = plan(&[Addon::Docker], Preset::Developer);
    let mut seen = 0;
    for step in p.build.iter().chain(p.post.iter()) {
        if matches!(
            step,
            Step::AptBootstrap | Step::AptInstall { .. } | Step::SecurityUpdates
        ) {
            let acts = lower(step, &secrets()).unwrap();
            let s = script_of(&acts[0]);
            assert!(
                s.contains("Acquire::http::Timeout=20") && s.contains("Acquire::https::Timeout=20"),
                "{s}"
            );
            assert!(
                s.contains("Acquire::Retries=3") && s.contains("DPkg::Lock::Timeout"),
                "{s}"
            );
            assert!(
                s.contains("timeout 120 apt-get") && s.contains("timeout \"$t\" apt-get"),
                "{s}"
            );
            assert!(
                s.contains("for i in 1 2 3 4") && s.contains("for i in 1 2 3"),
                "{s}"
            );
            assert!(s.contains("apt_update\n"), "{s}");
            // The executor-level limit leaves room for the retries.
            let Action::Exec(r) = &acts[0] else { panic!() };
            assert!(r.timeout.as_secs() >= 1800);
            seen += 1;
        }
    }
    assert_eq!(seen, 3);
}

#[test]
fn repo_step_verifies_the_pinned_fingerprint_and_pushes_the_pin() {
    let p = Catalog::embedded()
        .resolve(
            RecipeId {
                distro: Distro::Ubuntu2404,
                desktop: Desktop::Xfce,
                preset: Preset::Basic,
            },
            &[],
        )
        .unwrap();
    let repo = p
        .build
        .iter()
        .find(|s| matches!(s, Step::AptRepo(_)))
        .unwrap();
    let acts = lower(repo, &Secrets::none()).unwrap();
    let s = script_of(&acts[0]);
    assert!(
        s.contains("'738BEB9321D1AAEC13EA9391AEBDF4819BE21867'"),
        "{s}"
    );
    assert!(s.contains("key fingerprint mismatch") && s.contains("exit 1"));
    assert!(s.contains("Signed-By") && s.contains("/etc/apt/keyrings/mozillateam.gpg"));
    let Action::Push(f) = &acts[1] else {
        panic!("{acts:?}")
    };
    assert_eq!(f.path, "/etc/apt/preferences.d/mozillateam.pref");
    let pin = String::from_utf8_lossy(&f.content);
    assert!(pin.contains("Pin: origin ppa.launchpadcontent.net\nPin-Priority: 1001"));
    assert!(pin.contains("Package: *\nPin: origin ppa.launchpadcontent.net\nPin-Priority: 100"));
    // Ubuntu's snap-installing transitional firefox is never a candidate, PPA reachable or not.
    assert!(
        pin.contains("Pin: release o=Ubuntu\nPin-Priority: -1"),
        "{pin}"
    );
    // A repository whose index cannot be fetched fails the update (and is retried) instead of
    // being dropped with a warning, which would also drop its pins.
    let install = p
        .build
        .iter()
        .find(|s| matches!(s, Step::AptInstall { .. }))
        .unwrap();
    let install_acts = lower(install, &Secrets::none()).unwrap();
    let i = script_of(&install_acts[0]);
    assert!(i.contains("update -qq --error-on=any"), "{i}");
}

#[test]
fn file_and_user_steps_lower_to_quoted_commands() {
    let p = plan(&[Addon::Docker], Preset::Basic);
    let file = p
        .build
        .iter()
        .find(|s| matches!(s, Step::WriteFile(f) if f.path == "/etc/hx/xorg-dummy.conf"))
        .unwrap();
    let acts = lower(file, &Secrets::none()).unwrap();
    assert_eq!(acts.len(), 2, "root-owned files need no chown: {acts:?}");
    assert!(script_of(&acts[0]).contains("install -d -m 0755 '/etc/hx'"));
    let Action::Push(f) = &acts[1] else { panic!() };
    assert_eq!(
        (f.path.as_str(), f.mode),
        ("/etc/hx/xorg-dummy.conf", 0o644)
    );

    let user = p
        .build
        .iter()
        .find(|s| matches!(s, Step::EnsureUser(_)))
        .unwrap();
    let s = script_of(&lower(user, &Secrets::none()).unwrap()[0]).to_string();
    assert!(
        s.contains("--uid 1000")
            && s.contains("n='desk'")
            && s.contains("passwd -l")
            && s.contains("'docker'"),
        "{s}"
    );
    assert!(s.contains("userdel -r ubuntu"));

    let svc = p
        .build
        .iter()
        .find(|s| matches!(s, Step::EnableServices { .. }))
        .unwrap();
    let s = script_of(&lower(svc, &Secrets::none()).unwrap()[0]).to_string();
    assert!(
        s.contains("systemctl enable 'docker.service'")
            && s.contains("systemctl --global enable 'hx-xsession.service'")
    );
    assert!(s.contains("loginctl enable-linger 'desk'"));
}

#[test]
fn user_commands_run_through_runuser_with_a_home_directory() {
    let p = plan(&[], Preset::Developer);
    let cmd = p
        .post
        .iter()
        .find(|s| matches!(s, Step::Command(c) if c.as_user.is_some() && c.optional))
        .unwrap();
    let Action::Exec(r) = &lower(cmd, &Secrets::none()).unwrap()[0] else {
        panic!()
    };
    assert_eq!(
        &r.argv[..6],
        ["runuser", "-u", "desk", "--", "env", "HOME=/home/desk"]
    );
    assert_eq!(r.cwd.as_deref(), Some("/home/desk"));
    assert_eq!(r.timeout.as_secs(), 600);
}

/// Every generated and recipe-supplied script must at least parse as bash.
#[test]
fn all_scripts_of_all_recipes_are_syntactically_valid_bash() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut checked = 0;
    for rid in RecipeId::all() {
        let p = Catalog::embedded().resolve(rid, &[Addon::Docker]).unwrap();
        for step in p.build.iter().chain(p.post.iter()) {
            for a in lower(step, &secrets()).unwrap() {
                let Action::Exec(r) = a else { continue };
                if r.argv.first().map(String::as_str) != Some("bash")
                    && r.argv.first().map(String::as_str) != Some("runuser")
                {
                    continue;
                }
                let script = r.argv.last().unwrap();
                let mut c = Command::new("bash")
                    .arg("-n")
                    .stdin(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                c.stdin
                    .take()
                    .unwrap()
                    .write_all(script.as_bytes())
                    .unwrap();
                let out = c.wait_with_output().unwrap();
                assert!(
                    out.status.success(),
                    "{} in {}: {}\n{script}",
                    r.label,
                    p.name,
                    String::from_utf8_lossy(&out.stderr)
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 100, "{checked}");
}
