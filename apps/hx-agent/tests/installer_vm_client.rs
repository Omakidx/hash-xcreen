//! The client half of the CI VM cells (`.github/workflows/installer-vm.yml`,
//! `tests/installer-vm/`). Two `#[ignore]` tests, driven by environment variables, that the cell
//! script runs on the CI runner:
//!
//! * `vm_secrets`: makes the secrets of one cell (a password, a PIN and a pairing token) and
//!   writes `$HX1E_VM_DIR/{password,pin,token,frames.bin}` (0600). `frames.bin` is the stdin of
//!   `install.sh --ssh` (design C2). The secrets only ever travel on that pipe.
//! * `vm_login`: pairs devices and logs in with the PIN against `$HX1E_VM_ADDR` (`ip:port`),
//!   pinning `$HX1E_VM_SERVER_KEY` (64 hex digits, from the installer's result line). `$HX1E_VM_CREDS`
//!   is a comma separated list of `quic:<credential>` or `ws:<credential>` entries (a token
//!   `hxt1-...` or a code `XXXX-XXXX`); each pairs a new device over that transport and logs in.
//!   `HX1E_VM_STREAM=1` also waits for the first frame of the real desktop over the first entry.
//!
//! The same client code runs against the local nested container in `install_nested_incus.rs`,
//! where it is exercised on every run; here it is only compiled on a developer machine.
#![cfg(target_os = "linux")]

mod gateway_common;
mod install_harness;
mod relay_common;

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use hx_crypto::PairingToken;
use hx_transport::TransportPreference;
use install_harness::{client, frames, random_hex, random_pin};

fn dir() -> PathBuf {
    PathBuf::from(std::env::var("HX1E_VM_DIR").expect("HX1E_VM_DIR"))
}

fn write_private(name: &str, data: &[u8]) {
    let p = dir().join(name);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&p)
        .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    f.write_all(data).expect("write");
}

#[test]
#[ignore = "run by the installer-vm CI cells, with HX1E_VM_DIR"]
fn vm_secrets() {
    std::fs::create_dir_all(dir()).expect("dir");
    let password = format!("Pw-{}", random_hex(10));
    let pin = random_pin(14);
    let token = PairingToken::generate()
        .expect("token")
        .to_text()
        .to_string();
    write_private("password", password.as_bytes());
    write_private("pin", pin.as_bytes());
    write_private("token", token.as_bytes());
    write_private(
        "frames.bin",
        &frames::stream(&password, &pin, Some(&token), None),
    );
}

#[test]
#[ignore = "run by the installer-vm CI cells, with HX1E_VM_ADDR, HX1E_VM_SERVER_KEY, HX1E_VM_CREDS"]
fn vm_login() {
    let addr: std::net::SocketAddr = std::env::var("HX1E_VM_ADDR")
        .expect("HX1E_VM_ADDR")
        .parse()
        .expect("ip:port");
    let server = client::hex_to_key(&std::env::var("HX1E_VM_SERVER_KEY").expect("server key"));
    let pin = std::fs::read_to_string(dir().join("pin")).expect("pin file");
    let creds = std::env::var("HX1E_VM_CREDS").expect("HX1E_VM_CREDS");
    let stream = std::env::var("HX1E_VM_STREAM").is_ok_and(|v| v == "1");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    for (i, entry) in creds.split(',').filter(|e| !e.is_empty()).enumerate() {
        let (kind, cred) = entry.split_once(':').expect("kind:credential");
        let pref = match kind {
            "quic" => TransportPreference::Quic,
            "ws" => TransportPreference::WebSocket,
            other => panic!("unknown transport {other}"),
        };
        let t0 = std::time::Instant::now();
        let conn = rt.block_on(client::pair_and_login(
            addr,
            server,
            pref,
            &format!("hx1e-vm-{i}"),
            pin.trim(),
            Some(cred),
        ));
        eprintln!(
            "PASS pair + PIN login over {kind} in {} ms",
            t0.elapsed().as_millis()
        );
        if stream && i == 0 {
            let (bytes, ms) = rt
                .block_on(client::first_frame(conn, 120))
                .expect("a first frame of the desktop within 120 s");
            eprintln!("PASS first frame: an IDR of {bytes} bytes after {ms} ms");
        }
    }
}

/// Gate 1 "wrong PIN x5 revokes the device; revoked devices cannot connect", against a real
/// installed server: pairs one device with `$HX1E_VM_CREDS` (a single `quic:` or `ws:` entry),
/// logs in once with the right PIN, then sends wrong PINs (waiting out each backoff) until the
/// server revokes the device, and finally checks that the right PIN is refused as `Revoked`.
#[test]
#[ignore = "run against an installed server, with HX1E_VM_ADDR, HX1E_VM_SERVER_KEY, HX1E_VM_CREDS"]
fn vm_wrong_pin() {
    use std::sync::Arc;
    use std::time::Duration;

    use hx_crypto::{Error, IdentityKey, PairClientOptions, PairingCredential, Pin};

    let addr: std::net::SocketAddr = std::env::var("HX1E_VM_ADDR")
        .expect("HX1E_VM_ADDR")
        .parse()
        .expect("ip:port");
    let server = client::hex_to_key(&std::env::var("HX1E_VM_SERVER_KEY").expect("server key"));
    let pin = std::fs::read_to_string(dir().join("pin")).expect("pin file");
    let pin = pin.trim().to_owned();
    // A wrong PIN of the same length: the last digit changed.
    let mut wrong = pin.clone();
    let last = wrong.pop().expect("a PIN");
    wrong.push(if last == '0' { '1' } else { '0' });
    let creds = std::env::var("HX1E_VM_CREDS").expect("HX1E_VM_CREDS");
    let (kind, cred) = creds.split_once(':').expect("kind:credential");
    let pref = match kind {
        "quic" => TransportPreference::Quic,
        "ws" => TransportPreference::WebSocket,
        other => panic!("unknown transport {other}"),
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let t = client::target(addr);
        let device = Arc::new(IdentityKey::generate().expect("device key"));
        let paired = hx_crypto::pair_device(
            &t,
            &device,
            &PairingCredential::parse(cred).expect("credential"),
            &PairClientOptions {
                preference: pref,
                device_name: "hx1e-wrong-pin".into(),
                ..Default::default()
            },
        )
        .await
        .expect("pairing");
        assert_eq!(paired.server_key, server, "the pinned server key");
        paired.finish().await;
        let opts = {
            use hx_proto::VideoCodec;
            use hx_proto::version::{Features, PROTOCOL_MINOR, capabilities};
            hx_crypto::SessionOptions {
                preference: pref,
                device_name: "hx1e-wrong-pin".into(),
                capabilities: capabilities(
                    &[VideoCodec::H264],
                    Features::defined_up_to(PROTOCOL_MINOR),
                ),
                ..Default::default()
            }
        };
        let login = |p: String| {
            let (t, device, opts) = (t.clone(), device.clone(), opts.clone());
            async move {
                tokio::time::timeout(
                    Duration::from_secs(60),
                    hx_crypto::connect_with_pin(&t, &device, server, &Pin::new(&p).expect("pin"), &opts),
                )
                .await
                .expect("an answer in time")
            }
        };
        drop(login(pin.clone()).await.expect("the right PIN logs in first"));
        eprintln!("PASS the paired device logs in with the right PIN");
        let mut wrong_answers = 0;
        for _ in 0..20 {
            match login(wrong.clone()).await {
                Err(Error::WrongPin {
                    attempts_left,
                    retry_after,
                }) => {
                    wrong_answers += 1;
                    eprintln!("wrong PIN {wrong_answers}: {attempts_left} left, retry after {retry_after:?}");
                    tokio::time::sleep(retry_after + Duration::from_millis(200)).await;
                }
                Err(Error::Backoff { retry_after }) => {
                    tokio::time::sleep(retry_after + Duration::from_millis(200)).await;
                }
                Err(Error::Revoked) => break,
                Err(e) => panic!("unexpected answer to a wrong PIN: {e}"),
                Ok(_) => panic!("a wrong PIN logged in"),
            }
        }
        assert!(
            (4..=5).contains(&wrong_answers),
            "the device is revoked by the fifth wrong PIN ({wrong_answers} WrongPin answers)"
        );
        eprintln!("PASS revoked after {} wrong PINs", wrong_answers + usize::from(wrong_answers == 4));
        // A revoked key is refused like an unknown one (protocol.md: `Refuse{UNAUTHORIZED}`,
        // the same uniform text); `Revoked` is what a session that is cut off sees.
        match login(pin.clone()).await {
            Err(Error::Revoked)
            | Err(Error::Refused {
                reason: hx_proto::pb::RefuseReason::Unauthorized,
                ..
            }) => eprintln!("PASS the revoked device is refused with the right PIN"),
            Err(e) => panic!("the revoked device got another refusal: {e}"),
            Ok(_) => panic!("a revoked device logged in"),
        }
    });
}
