//! Secrets: a password, a PIN and a pairing token are taken only from the hidden terminal prompt
//! (or generated), travel only in kind-2 secret frames, and appear nowhere else: not in argv, the
//! environment, a protobuf body, the CLI's output, or what it asks.

mod cli_common;

use std::path::Path;
use std::sync::Arc;

use cli_common::*;
use hx_ipc::admin::pb as apb;
use hx_ipc::privd::pb::{self, request::Command, response::Result as R};

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// The secret is not in this process's own command line or environment (the CLI runs in the
/// test process here, and sets neither).
fn assert_not_in_process_state(secret: &[u8]) {
    for f in ["/proc/self/cmdline", "/proc/self/environ"] {
        let data = std::fs::read(f).unwrap_or_default();
        assert!(!contains(&data, secret), "{f} contains the secret");
    }
}

fn stand_ins() -> (PrivdHandler, AdminHandler) {
    let p: PrivdHandler = Arc::new(|req, _s| {
        Box::pin(async move {
            match req.command.expect("a command") {
                Command::SetUserPassword(_) => R::SetUserPassword(Default::default()).into(),
                Command::PepperEnrol(_) => R::PepperEnrol(pb::PepperEnrolResult {
                    mac: vec![7u8; 32].into(),
                    version: 1,
                })
                .into(),
                _ => privd_error(pb::ErrorCode::Unimplemented, "no").into(),
            }
        })
    });
    let a: AdminHandler = Arc::new(|req, _s| {
        Box::pin(async move {
            use apb::request::Command as C;
            match req.command.expect("a command") {
                C::SetPasswordVerifier(_) => {
                    apb::response::Result::SetPasswordVerifier(Default::default())
                }
                C::SetPinVerifier(_) => apb::response::Result::SetPinVerifier(Default::default()),
                C::CreatePairingToken(_) => {
                    apb::response::Result::CreatePairingToken(apb::CreatePairingTokenResult {
                        expires_at_unix_s: 1,
                    })
                }
                _ => admin_error(pb::ErrorCode::Unimplemented, "no"),
            }
        })
    });
    (p, a)
}

async fn stack() -> (
    tempfile::TempDir,
    hx_agent::cli::Config,
    ScriptedPrivd,
    ScriptedAdmin,
) {
    let dir = private_tempdir();
    let (ph, ah) = stand_ins();
    let p = ScriptedPrivd::start(dir.path(), "p.sock", PrivdOptions::default(), ph).await;
    let a = ScriptedAdmin::start(dir.path(), "a.sock", "0.1.0", ah).await;
    let mut cfg = unreachable_config(dir.path());
    cfg.privd_socket = p.path.clone();
    cfg.admin_socket = a.path.clone();
    (dir, cfg, p, a)
}

#[tokio::test]
async fn a_linux_password_travels_only_as_a_secret_frame() {
    let (_d, cfg, p, a) = stack().await;
    let pw: &[u8] = b"Tr0ub4dor&3-correct-horse";
    let r = cli(&cfg, &["desktop", "password"], &[pw, pw], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");

    // SetUserPassword: one secret frame, slot 0, exactly the password; PepperEnrol: a 32-byte
    // Argon2id output, not the password.
    let secrets = p.secrets.lock().unwrap().clone();
    assert_eq!(secrets.len(), 2, "{secrets:?}");
    assert_eq!((secrets[0].1, secrets[0].2.as_slice()), (0, pw));
    assert_eq!(secrets[1].2.len(), 32);
    assert_ne!(secrets[1].2.as_slice(), pw);
    let reqs = p.requests.lock().unwrap().clone();
    assert_eq!(
        reqs[0].secret_slots[0].kind,
        pb::SecretKind::UserPassword as i32
    );
    assert!(!reqs[0].secret_slots[0].sealed);
    assert_eq!(
        reqs[1].secret_slots[0].kind,
        pb::SecretKind::MacInput as i32
    );

    // No protobuf body, on either socket, contains the password, and neither does the output.
    for body in p
        .encoded
        .lock()
        .unwrap()
        .iter()
        .chain(a.encoded.lock().unwrap().iter())
    {
        assert!(!contains(body, pw), "a request body carries the password");
    }
    assert!(
        a.secrets.lock().unwrap().is_empty(),
        "gatewayd never receives a secret here"
    );
    assert!(!contains(r.stdout.as_bytes(), pw) && !contains(r.stderr.as_bytes(), pw));
    assert!(r.asked.iter().all(|q| !contains(q.as_bytes(), pw)));
    assert_not_in_process_state(pw);

    // The verifier given to gatewayd is the documented record, and carries no password.
    let reqs = a.requests.lock().unwrap().clone();
    let Some(apb::request::Command::SetPasswordVerifier(v)) = &reqs[0].command else {
        panic!("{reqs:?}")
    };
    let text = std::str::from_utf8(&v.verifier).unwrap();
    assert!(text.starts_with("hx-pv1$m=64,t=1,p=1$"), "{text}");
    assert!(!text.contains("Tr0ub4dor"));
}

#[tokio::test]
async fn a_pin_travels_only_inside_an_argon2id_output() {
    let (_d, cfg, p, a) = stack().await;
    let r = cli(&cfg, &["pin", "set"], &[b"482913", b"482913"], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    let secrets = p.secrets.lock().unwrap().clone();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].2.len(), 32, "only the hash output reaches privd");
    assert_ne!(secrets[0].2.as_slice(), b"482913");
    for body in p
        .encoded
        .lock()
        .unwrap()
        .iter()
        .chain(a.encoded.lock().unwrap().iter())
    {
        assert!(!contains(body, b"482913"));
    }
    assert!(a.secrets.lock().unwrap().is_empty());
    assert!(!r.stdout.contains("482913") && !r.stderr.contains("482913"));
    assert_not_in_process_state(b"482913");
}

#[tokio::test]
async fn a_pairing_token_travels_only_as_a_secret_frame_to_gatewayd() {
    let (_d, cfg, p, a) = stack().await;
    let token = hx_crypto::PairingToken::generate().unwrap().to_text();
    let r = cli(
        &cfg,
        &["pairing", "token", "--ttl", "5m"],
        &[token.as_bytes()],
        &[],
    )
    .await;
    assert_eq!(r.code, 0, "{r:?}");
    let secrets = a.secrets.lock().unwrap().clone();
    assert_eq!(secrets.len(), 1);
    assert_eq!(
        (secrets[0].1, secrets[0].2.as_slice()),
        (0, token.as_bytes())
    );
    let reqs = a.requests.lock().unwrap().clone();
    assert_eq!(
        reqs[0].secret_slots[0].kind,
        apb::AdminSecretKind::PairingToken as i32
    );
    let Some(apb::request::Command::CreatePairingToken(c)) = &reqs[0].command else {
        panic!()
    };
    assert_eq!(c.expires_in_s, 300);
    for body in a
        .encoded
        .lock()
        .unwrap()
        .iter()
        .chain(p.encoded.lock().unwrap().iter())
    {
        assert!(
            !contains(body, token.as_bytes()),
            "a request body carries the token"
        );
    }
    assert!(p.commands().is_empty(), "privd never hears of the token");
    assert!(!r.stdout.contains(token.as_str()) && !r.stderr.contains(token.as_str()));
    assert!(r.asked.iter().all(|q| !q.contains(token.as_str())));
    assert_not_in_process_state(token.as_bytes());
    // Surrounding whitespace from the terminal does not change what is sent.
    let mut padded = token.as_bytes().to_vec();
    padded.extend_from_slice(b"  ");
    let r = cli(&cfg, &["pairing", "token"], &[&padded], &[]).await;
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(a.secrets.lock().unwrap()[1].2.as_slice(), token.as_bytes());
}

#[tokio::test]
async fn no_option_takes_a_password_or_a_pin_and_nothing_reaches_a_daemon() {
    let (_d, cfg, p, a) = stack().await;
    for args in [
        vec!["desktop", "password", "--password", "hunter2"],
        vec!["desktop", "password", "--password=hunter2"],
        vec!["pin", "set", "--pin", "482913"],
        vec!["pin", "set", "--pin=482913"],
        vec!["desktop", "password", "--new-password", "x"],
        vec!["pairing", "token", "--secret", "x"],
    ] {
        let r = cli(&cfg, &args, &[], &[]).await;
        assert_eq!(r.code, 2, "{args:?}: {r:?}");
        assert!(
            r.stderr.contains("never takes a secret"),
            "{args:?}: {}",
            r.stderr
        );
        assert!(r.asked.is_empty());
    }
    assert!(p.commands().is_empty() && a.commands().is_empty());
}

#[tokio::test]
async fn the_cli_reads_no_environment_and_runs_one_fixed_program() {
    // The source of the CLI library: no environment access at all, and `Command::new` only for
    // journalctl.
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli"),
        &mut files,
    );
    assert!(files.len() > 15, "{files:?}");
    let mut spawns = Vec::new();
    for f in &files {
        let src = std::fs::read_to_string(f).unwrap();
        // Strip comments so that documentation may talk about the environment.
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for bad in [
            "env::var",
            "env::args",
            "std::env",
            "set_var",
            "remove_var",
            "getenv",
        ] {
            assert!(!code.contains(bad), "{} uses {bad}", f.display());
        }
        for bad in [
            "sh -c",
            "\"/bin/sh\"",
            "\"sh\"",
            "tracing::",
            "println!(",
            "eprintln!(",
        ] {
            assert!(!code.contains(bad), "{} uses {bad}", f.display());
        }
        if code.contains("Command::new") {
            spawns.push(f.file_name().unwrap().to_string_lossy().into_owned());
        }
    }
    assert_eq!(
        spawns,
        ["logs.rs"],
        "the only program the CLI starts is journalctl"
    );
}

#[tokio::test]
async fn the_binary_reads_nothing_from_argv_env_or_stdin_for_secrets() {
    // Without root the binary stops at the uid check, which is also where an `--password`
    // flag is refused as an unknown option: both before any secret could be read.
    let bin = env!("CARGO_BIN_EXE_hx-agent");
    let out = std::process::Command::new(bin)
        .args(["desktop", "password", "--password", "hunter2"])
        .env_clear()
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("never takes a secret"), "{err}");
    assert!(
        !err.contains("hunter2 "),
        "the value is not echoed back: {err}"
    );
}
