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
