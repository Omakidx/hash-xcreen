//! Connect, host-key confirmation, preflight, install streaming and lost-connection behaviour
//! against an in-process russh server (no sshd).

mod support;

use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use hx_agent::install::stdin::read_frames;
use hx_sshsetup::progress::LogStream;
use hx_sshsetup::{
    Auth, ConnectOptions, Connection, Credentials, ErrorKind, InstallEvent, InstallOptions,
    InstallRequest, InstallScript, KeySource, Phase, Secrets, SshSetupError, StageState, SudoMode,
    install, preflight, probe_host_key,
};
use support::*;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_owned())
}

fn opts() -> ConnectOptions {
    ConnectOptions {
        handshake_timeout: Duration::from_secs(20),
        auth_timeout: Duration::from_secs(20),
        ..Default::default()
    }
}

fn pw_creds(pw: &str) -> Credentials {
    Credentials {
        user: "alice".into(),
        auth: Auth::Password(z(pw)),
    }
}

fn default_run() -> Plan {
    Arc::new(|_| vec![out(&ok_lines(KEY_HEX)), Action::Exit(0)])
}

fn fake(sudo: Sudo, run: Plan) -> Fake {
    Fake::new(shell(sudo, HEALTHY_PREFLIGHT.to_owned(), run))
}

async fn connect(f: &Fake) -> Connection {
    Connection::connect_stream(
        f.connect(),
        &f.fingerprint(),
        &pw_creds("right-pw"),
        &opts(),
    )
    .await
    .expect("connect")
}

fn secrets() -> Secrets {
    Secrets::new(z("desktop-pw"), z("482915")).unwrap()
}

fn request() -> InstallRequest {
    InstallRequest::new(
        InstallScript::Bytes(b"#!/bin/sh\nexit 0\n".to_vec()),
        InstallOptions {
            distro: Some("ubuntu-24.04".into()),
            docker: true,
            ..Default::default()
        },
    )
}

async fn run_install(
    c: &Connection,
    req: &InstallRequest,
    s: &Secrets,
) -> (
    Result<hx_sshsetup::InstallResult, SshSetupError>,
    Vec<InstallEvent>,
) {
    let (tx, mut rx) = mpsc::channel(256);
    let r = install(c, req, s, &tx).await;
    drop(tx);
    let mut ev = Vec::new();
    while let Some(e) = rx.recv().await {
        ev.push(e);
    }
    (r, ev)
}

// ---------------------------------------------------------------- host key and auth

#[tokio::test]
async fn probe_returns_the_openssh_fingerprint_and_authenticates_nothing() {
    let f = fake(Sudo::Root, default_run());
    let hk = probe_host_key_via(&f).await;
    assert_eq!(hk.fingerprint, f.fingerprint());
    assert!(hk.fingerprint.starts_with("SHA256:"));
    assert!(!hk.fingerprint.ends_with('='), "OpenSSH prints no padding");
    assert_eq!(hk.algorithm, "ssh-ed25519");
    assert_eq!(
        f.auth_attempts(),
        0,
        "no credential before the user trusts the key"
    );
}

async fn probe_via_stream(f: &Fake) -> hx_sshsetup::HostKey {
    hx_sshsetup::ssh::probe_host_key_stream(f.connect(), &opts())
        .await
        .expect("probe")
}

async fn probe_host_key_via(f: &Fake) -> hx_sshsetup::HostKey {
    probe_via_stream(f).await
}

#[tokio::test]
async fn probe_over_tcp_reports_a_refused_connection() {
    // Port 1 on localhost: nothing listens.
    let r = probe_host_key(&hx_sshsetup::SshTarget::new("127.0.0.1", 1), &opts()).await;
    let e = r.unwrap_err();
    assert!(matches!(e, SshSetupError::Connect(_)), "{e:?}");
    assert_eq!(e.kind(), ErrorKind::Connection);
    assert!(e.is_retryable());
}

#[tokio::test]
async fn password_login_with_the_confirmed_fingerprint() {
    let f = fake(Sudo::Root, default_run());
    let c = connect(&f).await;
    assert_eq!(c.host_key().fingerprint, f.fingerprint());
    assert_eq!(c.user(), "alice");
    assert_eq!(f.auth_attempts(), 1);
    c.disconnect().await;
}

#[tokio::test]
async fn a_changed_host_key_stops_before_any_credential_is_sent() {
    let f = fake(Sudo::Root, default_run());
    let other = fingerprint(&key_from_seed(9));
    let e = Connection::connect_stream(f.connect(), &other, &pw_creds("right-pw"), &opts())
        .await
        .unwrap_err();
    match &e {
        SshSetupError::HostKeyChanged { expected, actual } => {
            assert_eq!(expected, &other);
            assert_eq!(actual, &f.fingerprint());
        }
        o => panic!("{o:?}"),
    }
    assert_eq!(e.kind(), ErrorKind::HostKey);
    assert!(!e.is_retryable());
    assert_eq!(f.auth_attempts(), 0);
}

#[tokio::test]
async fn a_wrong_password_is_auth_failed() {
    let f = fake(Sudo::Root, default_run());
    let e = Connection::connect_stream(f.connect(), &f.fingerprint(), &pw_creds("nope"), &opts())
        .await
        .unwrap_err();
    assert!(matches!(e, SshSetupError::AuthFailed), "{e:?}");
    assert_eq!(e.kind(), ErrorKind::Credentials);
}

#[tokio::test]
async fn key_login_from_pem_text_and_from_a_file() {
    let client = key_from_seed(5);
    let mut f = fake(Sudo::Root, default_run());
    f.client_key = Some(client.public_key().clone());
    f.password = None;
    let creds = Credentials {
        user: "alice".into(),
        auth: Auth::Key {
            source: KeySource::Pem(pem(&client)),
            passphrase: None,
        },
    };
    let c = Connection::connect_stream(f.connect(), &f.fingerprint(), &creds, &opts())
        .await
        .expect("pem key login");
    c.disconnect().await;

    let dir = std::env::temp_dir().join(format!("hx-sshsetup-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("id_ed25519");
    std::fs::write(&path, pem(&client).as_bytes()).unwrap();
    let creds = Credentials {
        user: "alice".into(),
        auth: Auth::Key {
            source: KeySource::Path(path),
            passphrase: None,
        },
    };
    let c = Connection::connect_stream(f.connect(), &f.fingerprint(), &creds, &opts())
        .await
        .expect("file key login");
    c.disconnect().await;
    let _ = std::fs::remove_dir_all(dir);

    // A key the server does not know.
    let creds = Credentials {
        user: "alice".into(),
        auth: Auth::Key {
            source: KeySource::Pem(pem(&key_from_seed(6))),
            passphrase: None,
        },
    };
    let e = Connection::connect_stream(f.connect(), &f.fingerprint(), &creds, &opts())
        .await
        .unwrap_err();
    assert!(matches!(e, SshSetupError::AuthFailed), "{e:?}");
}

#[tokio::test]
async fn unusable_keys_are_typed_and_never_touch_the_network() {
    let f = fake(Sudo::Root, default_run());
    for (src, want_kind) in [
        (KeySource::Pem(z("not a key")), ErrorKind::Credentials),
        (
            KeySource::Path("/nonexistent/hx-key".into()),
            ErrorKind::Credentials,
        ),
    ] {
        let creds = Credentials {
            user: "alice".into(),
            auth: Auth::Key {
                source: src,
                passphrase: None,
            },
        };
        let e = Connection::connect_stream(f.connect(), &f.fingerprint(), &creds, &opts())
            .await
            .unwrap_err();
        assert!(matches!(e, SshSetupError::KeyUnusable(_)), "{e:?}");
        assert_eq!(e.kind(), want_kind);
    }
    assert_eq!(f.auth_attempts(), 0);
}

// ---------------------------------------------------------------- preflight

#[tokio::test]
async fn preflight_reads_the_servers_real_values() {
    let f = fake(Sudo::Root, default_run());
    let c = connect(&f).await;
    let r = preflight(&c, 443).await.expect("preflight");
    assert!(r.passed(), "{:?}", r.failures());
    assert_eq!(r.facts.mem_mib, Some(7933));
    assert_eq!(r.facts.cpus, Some(4));
    assert_eq!(r.facts.disk_free_gib, Some(60));
    assert_eq!(r.facts.sudo, Some(SudoMode::NeedsPassword));
    // One read-only exec with a constant script; nothing from the caller is interpolated.
    let ex = f.execs();
    assert_eq!(ex.len(), 1);
    assert_eq!(ex[0].command, "sh -s");
    let script = String::from_utf8_lossy(&ex[0].stdin);
    assert!(script.contains("/proc/meminfo") && !script.contains("rm "));
}

#[tokio::test]
async fn preflight_failure_lists_what_is_missing() {
    let weak = HEALTHY_PREFLIGHT
        .replace("8123456 kB", "2000000 kB")
        .replace("@cpus\n4", "@cpus\n1")
        .replace("62914560", "1048576");
    let f = Fake::new(shell(Sudo::Root, weak, default_run()));
    let c = connect(&f).await;
    let r = preflight(&c, 443).await.unwrap();
    let e = r.require_ok().unwrap_err();
    match &e {
        SshSetupError::RequirementFailed(v) => {
            let ids: Vec<_> = v.iter().map(|c| c.id).collect();
            assert_eq!(ids, ["memory", "cpus", "disk"]);
            assert_eq!(v[0].actual, "1953 MiB");
            assert_eq!(v[0].required, "3584 MiB (4 GB class)");
        }
        o => panic!("{o:?}"),
    }
    assert_eq!(e.kind(), ErrorKind::Requirements);
}

// ---------------------------------------------------------------- install

fn frames_of(e: &Exec) -> Vec<u8> {
    if e.command.starts_with("sudo -S") {
        let at = e.stdin.iter().position(|b| *b == b'\n').expect("sudo line");
        e.stdin[at + 1..].to_vec()
    } else {
        e.stdin.clone()
    }
}

#[tokio::test]
async fn a_root_install_streams_events_and_returns_the_typed_result() {
    let f = fake(Sudo::Root, default_run());
    let c = connect(&f).await;
    let (r, ev) = run_install(&c, &request(), &secrets()).await;
    let r = r.expect("install");
    assert_eq!(r.server_public_key, KEY_HEX);
    assert_eq!(r.addresses, ["203.0.113.9"]);
    assert_eq!(r.port, 443);
    assert_eq!(r.pairing, hx_sshsetup::PairingKind::Token);
    assert_eq!(r.desktop.as_ref().unwrap().path_taken, "BUILD");
    assert_eq!(r.warnings, ["apt-get update was slow", "slow mirror"]);

    // Phases, then the installer's lines in order.
    let phases: Vec<_> = ev
        .iter()
        .filter_map(|e| match e {
            InstallEvent::Phase(p) => Some(*p),
            _ => None,
        })
        .collect();
    assert_eq!(
        phases,
        [Phase::SudoCheck, Phase::Upload, Phase::Run, Phase::Cleanup]
    );
    let stages: Vec<_> = ev
        .iter()
        .filter_map(|e| match e {
            InstallEvent::Stage { id, state, n, .. } => Some((id.as_str(), state.clone(), *n)),
            _ => None,
        })
        .collect();
    assert_eq!(
        stages,
        [
            ("bootstrap-preflight", StageState::Start, None),
            ("bootstrap-preflight", StageState::Done, None),
            ("preflight", StageState::Start, Some(1)),
            ("preflight", StageState::Done, Some(1)),
        ]
    );
    assert!(
        ev.iter()
            .any(|e| matches!(e, InstallEvent::Step { percent: None, .. }))
    );
    assert!(ev.iter().any(|e| matches!(e, InstallEvent::Warn { .. })));

    // What the server saw: the command line holds options but no secret; the frames on stdin
    // are accepted by the real server-side parser; the temp directory was removed.
    let ex = f.execs();
    let run = ex.iter().find(|e| e.command.contains("--ssh")).unwrap();
    assert!(
        run.command
            .starts_with("sh '/tmp/hx-setup.AbC123/install.sh' --ssh --progress json")
    );
    assert!(run.command.contains("--distro 'ubuntu-24.04' --docker"));
    for secret in ["desktop-pw", "482915", "right-pw"] {
        assert!(
            ex.iter().all(|e| !e.command.contains(secret)),
            "{secret} leaked into a command line"
        );
    }
    let fr = read_frames(&mut Cursor::new(frames_of(run)), true).expect("installer parser");
    assert_eq!(
        fr.password.as_deref().map(Vec::as_slice),
        Some(&b"desktop-pw"[..])
    );
    assert_eq!(fr.pin.as_deref().map(Vec::as_slice), Some(&b"482915"[..]));
    assert!(ex.last().unwrap().command.contains("rm -rf --"));
    let upload = ex.iter().find(|e| e.command.contains("cat >")).unwrap();
    assert_eq!(upload.stdin, b"#!/bin/sh\nexit 0\n");
}

#[tokio::test]
async fn install_with_passwordless_sudo_uses_sudo_n_and_sends_no_password_line() {
    let f = fake(Sudo::Passwordless, default_run());
    let c = connect(&f).await;
    let (r, _) = run_install(&c, &request(), &secrets()).await;
    r.expect("install");
    let ex = f.execs();
    let run = ex.iter().find(|e| e.command.contains("--ssh")).unwrap();
    assert!(
        run.command
            .starts_with("sudo -n sh '/tmp/hx-setup.AbC123/install.sh'")
    );
    assert!(run.stdin.starts_with(b"HXI1"));
}

#[tokio::test]
async fn install_with_a_sudo_password_sends_it_first_and_only_in_stdin() {
    let f = fake(Sudo::Password("sudo-secret"), default_run());
    let c = connect(&f).await;
    let s = secrets().with_sudo_password(z("sudo-secret")).unwrap();
    let (r, _) = run_install(&c, &request(), &s).await;
    r.expect("install");
    let ex = f.execs();
    let run = ex.iter().find(|e| e.command.contains("--ssh")).unwrap();
    assert!(run.command.starts_with("sudo -S -k -p '' sh "));
    assert!(run.stdin.starts_with(b"sudo-secret\nHXI1"));
    assert!(ex.iter().all(|e| !e.command.contains("sudo-secret")));
    read_frames(&mut Cursor::new(frames_of(run)), true).expect("installer parser");
}

#[tokio::test]
async fn a_wrong_sudo_password_stops_before_any_secret_is_sent() {
    let f = fake(Sudo::Password("sudo-secret"), default_run());
    let c = connect(&f).await;
    let s = secrets().with_sudo_password(z("guess")).unwrap();
    let (r, ev) = run_install(&c, &request(), &s).await;
    let e = r.unwrap_err();
    assert!(matches!(e, SshSetupError::SudoPasswordWrong), "{e:?}");
    assert_eq!(e.kind(), ErrorKind::Sudo);
    assert!(e.is_retryable());
    // Nothing was uploaded or run; the C2 frames never went on the wire.
    assert!(
        f.execs()
            .iter()
            .all(|x| !x.stdin.windows(4).any(|w| w == b"HXI1"))
    );
    assert!(
        !ev.iter()
            .any(|e| matches!(e, InstallEvent::Phase(Phase::Upload)))
    );
}

#[tokio::test]
async fn a_missing_sudo_password_and_no_sudo_are_typed() {
    let f = fake(Sudo::Password("x"), default_run());
    let c = connect(&f).await;
    let (r, _) = run_install(&c, &request(), &secrets()).await;
    assert!(matches!(
        r.unwrap_err(),
        SshSetupError::SudoPasswordRequired
    ));

    let f = fake(Sudo::None, default_run());
    let c = connect(&f).await;
    let (r, _) = run_install(&c, &request(), &secrets()).await;
    assert!(matches!(r.unwrap_err(), SshSetupError::SudoUnavailable));
}

#[tokio::test]
async fn an_installer_failure_carries_stage_code_message_and_retryable() {
    let run: Plan = Arc::new(|_| {
        vec![
            out(
                "{\"v\":1,\"t\":\"stage\",\"id\":\"incus\",\"n\":3,\"of\":19,\"state\":\"start\",\"ms\":0}\n",
            ),
            err("hx install: package source unreachable\n"),
            out(
                "{\"v\":1,\"t\":\"stage\",\"id\":\"incus\",\"n\":3,\"of\":19,\"state\":\"fail\",\"ms\":50000}\n",
            ),
            out(
                "{\"v\":1,\"t\":\"result\",\"ok\":false,\"exit\":1,\"stage\":\"incus\",\"code\":\"UNAVAILABLE\",\"message\":\"package source unreachable\",\"retryable\":true}\n",
            ),
            Action::Exit(1),
        ]
    });
    let f = fake(Sudo::Root, run);
    let c = connect(&f).await;
    let (r, ev) = run_install(&c, &request(), &secrets()).await;
    let e = r.unwrap_err();
    match &e {
        SshSetupError::InstallerFailed(x) => {
            assert_eq!(x.stage, "incus");
            assert_eq!(x.code, "UNAVAILABLE");
            assert_eq!(x.message, "package source unreachable");
            assert!(x.retryable);
            assert_eq!(x.exit, 1);
        }
        o => panic!("{o:?}"),
    }
    assert_eq!(e.kind(), ErrorKind::Installer);
    assert!(e.is_retryable());
    // The human text on stderr reaches the log.
    assert!(ev.iter().any(|e| matches!(e, InstallEvent::Log { stream: LogStream::Stderr, text } if text.contains("unreachable"))));
}

#[tokio::test]
async fn a_hard_failure_is_not_retryable() {
    let run: Plan = Arc::new(|_| {
        vec![
            out(
                "{\"v\":1,\"t\":\"stage\",\"id\":\"bootstrap-verify\",\"state\":\"fail\"}\n{\"v\":1,\"t\":\"result\",\"ok\":false,\"exit\":10,\"stage\":\"bootstrap-verify\",\"code\":\"VERIFY\",\"message\":\"the release manifest signature is not valid\",\"retryable\":false}\n",
            ),
            Action::Exit(10),
        ]
    });
    let f = fake(Sudo::Root, run);
    let c = connect(&f).await;
    let (r, _) = run_install(&c, &request(), &secrets()).await;
    let e = r.unwrap_err();
    assert!(!e.is_retryable());
}

#[tokio::test]
async fn a_lost_connection_mid_install_names_the_running_stage() {
    let run: Plan = Arc::new(|_| {
        vec![
            out(
                "{\"v\":1,\"t\":\"stage\",\"id\":\"packages\",\"n\":2,\"of\":19,\"state\":\"done\",\"ms\":1}\n",
            ),
            out(
                "{\"v\":1,\"t\":\"stage\",\"id\":\"incus\",\"n\":3,\"of\":19,\"state\":\"start\",\"ms\":0}\n",
            ),
            Action::Delay(20),
            Action::Disconnect,
        ]
    });
    let f = fake(Sudo::Root, run);
    let c = connect(&f).await;
    let (r, ev) = run_install(&c, &request(), &secrets()).await;
    let e = r.unwrap_err();
    match &e {
        SshSetupError::ConnectionLost { last_stage } => {
            assert_eq!(last_stage.as_deref(), Some("incus"));
        }
        o => panic!("{o:?}"),
    }
    assert_eq!(e.kind(), ErrorKind::ConnectionLost);
    assert!(e.is_retryable());
    // The events that did arrive were delivered.
    assert!(
        ev.iter()
            .any(|e| matches!(e, InstallEvent::Stage { id, .. } if id == "packages"))
    );
    assert!(
        c.is_closed() || {
            tokio::time::sleep(Duration::from_millis(100)).await;
            c.is_closed()
        }
    );
}

#[tokio::test]
async fn resume_after_a_lost_connection_reruns_with_secrets_supplied_again() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let run: Plan = Arc::new(move |_| {
        if n2.fetch_add(1, Ordering::SeqCst) == 0 {
            vec![
                out(
                    "{\"v\":1,\"t\":\"stage\",\"id\":\"incus\",\"n\":3,\"of\":19,\"state\":\"start\",\"ms\":0}\n",
                ),
                Action::Disconnect,
            ]
        } else {
            let mut v = vec![out(
                "{\"v\":1,\"t\":\"stage\",\"id\":\"packages\",\"n\":2,\"of\":19,\"state\":\"skip\",\"ms\":0}\n",
            )];
            v.push(out(&ok_lines(KEY_HEX)));
            v.push(Action::Exit(0));
            v
        }
    });
    let f = fake(Sudo::Root, run);
    let c1 = connect(&f).await;
    let (r, _) = run_install(&c1, &request(), &secrets()).await;
    assert!(matches!(
        r.unwrap_err(),
        SshSetupError::ConnectionLost { .. }
    ));

    // New connection, same options, secrets built again.
    let c2 = connect(&f).await;
    let (r, ev) = run_install(&c2, &request(), &secrets()).await;
    r.expect("resumed install");
    assert!(ev.iter().any(
        |e| matches!(e, InstallEvent::Stage { id, state: StageState::Skip, .. } if id == "packages")
    ));
    let runs: Vec<_> = f
        .execs()
        .into_iter()
        .filter(|e| e.command.contains("--ssh"))
        .collect();
    assert_eq!(runs.len(), 2);
    for r in runs {
        read_frames(&mut Cursor::new(frames_of(&r)), true).expect("fresh frames both times");
    }
}

#[tokio::test]
async fn a_nonzero_exit_without_a_result_line_is_an_installer_failure() {
    let run: Plan = Arc::new(|_| {
        vec![
            out(
                "{\"v\":1,\"t\":\"stage\",\"id\":\"units\",\"n\":8,\"of\":19,\"state\":\"start\",\"ms\":0}\n",
            ),
            err("hx install: killed\n"),
            Action::Exit(137),
        ]
    });
    let f = fake(Sudo::Root, run);
    let c = connect(&f).await;
    let (r, _) = run_install(&c, &request(), &secrets()).await;
    match r.unwrap_err() {
        SshSetupError::InstallerFailed(x) => {
            assert_eq!(
                (x.stage.as_str(), x.code.as_str(), x.exit),
                ("units", "EXIT", 137)
            );
            assert_eq!(x.message, "hx install: killed");
        }
        o => panic!("{o:?}"),
    }
}

#[tokio::test]
async fn exit_zero_without_a_result_is_a_protocol_error() {
    let run: Plan = Arc::new(|_| vec![Action::Exit(0)]);
    let f = fake(Sudo::Root, run);
    let c = connect(&f).await;
    let (r, _) = run_install(&c, &request(), &secrets()).await;
    assert!(matches!(r.unwrap_err(), SshSetupError::Protocol(_)));
}

#[tokio::test]
async fn sudo_asking_again_inside_the_run_is_a_wrong_password() {
    // The password changed between the check and the run: sudo prints its retry text and exits.
    let run: Plan = Arc::new(|_| {
        vec![
            err("Sorry, try again.\nsudo: 1 incorrect password attempt\n"),
            Action::Exit(1),
        ]
    });
    let f = fake(Sudo::Password("pw"), run);
    let c = connect(&f).await;
    let s = secrets().with_sudo_password(z("pw")).unwrap();
    let (r, _) = run_install(&c, &request(), &s).await;
    assert!(matches!(r.unwrap_err(), SshSetupError::SudoPasswordWrong));
}

#[tokio::test]
async fn a_silent_installer_hits_the_run_timeout() {
    let run: Plan = Arc::new(|_| vec![Action::Hang]);
    let f = fake(Sudo::Root, run);
    let c = connect(&f).await;
    let mut req = request();
    req.run_timeout = Duration::from_millis(300);
    let (r, _) = run_install(&c, &req, &secrets()).await;
    assert!(matches!(r.unwrap_err(), SshSetupError::Timeout(_)));
}

#[tokio::test]
async fn closing_the_event_receiver_does_not_stop_the_install() {
    let f = fake(Sudo::Root, default_run());
    let c = connect(&f).await;
    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    let r = install(&c, &request(), &secrets(), &tx).await;
    assert!(r.is_ok());
}

#[tokio::test]
async fn bad_input_is_refused_before_anything_runs() {
    let f = fake(Sudo::Root, default_run());
    let c = connect(&f).await;
    let mut req = request();
    req.script = InstallScript::Bytes(b"not a script".to_vec());
    let (r, _) = run_install(&c, &req, &secrets()).await;
    assert!(matches!(r.unwrap_err(), SshSetupError::InvalidInput(_)));
    let mut req = request();
    req.options.hostname = Some("a b; rm -rf /".into());
    // Quoted, so this one is accepted as data; a leading dash is not.
    req.options.domain = Some("-x".into());
    let (r, _) = run_install(&c, &req, &secrets()).await;
    assert!(matches!(r.unwrap_err(), SshSetupError::InvalidInput(_)));
    assert!(f.execs().is_empty(), "nothing reached the server");
}

#[tokio::test]
async fn hostile_options_stay_inside_their_quotes() {
    let f = fake(Sudo::Root, default_run());
    let c = connect(&f).await;
    let mut req = request();
    req.options.hostname = Some("a b; rm -rf / $(x) `y` 'z'".into());
    let (r, _) = run_install(&c, &req, &secrets()).await;
    r.expect("install");
    let run = f
        .execs()
        .into_iter()
        .find(|e| e.command.contains("--ssh"))
        .unwrap();
    assert!(
        run.command
            .contains("--hostname 'a b; rm -rf / $(x) `y` '\\''z'\\'''"),
        "{}",
        run.command
    );
}

#[tokio::test]
async fn a_script_from_a_path_is_uploaded_byte_for_byte() {
    let f = fake(Sudo::Root, default_run());
    let c = connect(&f).await;
    let dir = std::env::temp_dir().join(format!("hx-sshsetup-script-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("install.sh");
    let body = b"#!/bin/sh\n# bytes \xff\x00 included\n".to_vec();
    std::fs::write(&p, &body).unwrap();
    let mut req = request();
    req.script = InstallScript::Path(p);
    let (r, _) = run_install(&c, &req, &secrets()).await;
    r.expect("install");
    let up = f
        .execs()
        .into_iter()
        .find(|e| e.command.contains("cat >"))
        .unwrap();
    assert_eq!(up.stdin, body);
    let _ = std::fs::remove_dir_all(dir);
}
