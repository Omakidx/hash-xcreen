//! The known-answer vectors of `installer/install.sh`'s openssl minisign verification (design D2).
//!
//! The vectors in `installer/tests/vectors/` are made by the `minisign` crate (an implementation
//! independent of both openssl and privd's `minisign-verify`), plus one genuinely legacy
//! (non-prehashed) signature made with openssl. This file:
//!
//! - regenerates them (`HX_KAT_REGEN=1 cargo test -p hx-agent --test installer_sh -- --ignored
//!   regenerate_vectors`; fresh throwaway keys each time, which also rewrites the KAT block of
//!   `install.sh`);
//! - checks that privd's own verifier (`UpdateKeys`) agrees with the expected outcome of the
//!   vectors it should agree on, so the shell and the daemon cannot drift apart;
//! - runs the shell suite (`installer/tests/run.sh`) under dash, and the release-dir hand-off
//!   suite (`installer/tests/handoff.sh`).

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

use hx_agent::privd::update::UpdateKeys;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn vectors() -> PathBuf {
    repo().join("installer/tests/vectors")
}

const MSG: &[u8] = b"hx installer known-answer test\n";
const TRUSTED: &str = "hx-manifest v0.0.0 channel=stable arch=x86_64";
const UNTRUSTED: &str = "hx installer known-answer test";

// ----- tiny base64 (the vectors need raw byte surgery) ---------------------------------------

const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64e(data: &[u8]) -> String {
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(ALPHA[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn b64d(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for ch in s.bytes().filter(|b| *b != b'=') {
        let v = ALPHA.iter().position(|a| *a == ch).expect("base64") as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    out
}

// ----- generation ----------------------------------------------------------------------------

fn sign(kp: &minisign::KeyPair, msg: &[u8], trusted: &str) -> String {
    minisign::sign(
        Some(&kp.pk),
        &kp.sk,
        Cursor::new(msg),
        Some(trusted),
        Some(UNTRUSTED),
    )
    .expect("sign")
    .into_string()
}

fn pk_file(kp: &minisign::KeyPair) -> String {
    kp.pk.to_box().expect("pk box").into_string()
}

/// Raw Ed25519 signature of `data` by the 32-byte `seed`, through the openssl CLI.
fn openssl_ed25519_sign(seed: &[u8], data: &[u8]) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let mut der = hex_to_bytes("302e020100300506032b657004220420");
    der.extend_from_slice(seed);
    fs::write(dir.path().join("k.der"), der).unwrap();
    fs::write(dir.path().join("d"), data).unwrap();
    let st = Command::new("openssl")
        .current_dir(dir.path())
        .args([
            "pkeyutl", "-sign", "-inkey", "k.der", "-keyform", "DER", "-rawin", "-in", "d", "-out",
            "s",
        ])
        .status()
        .expect("openssl");
    assert!(st.success());
    fs::read(dir.path().join("s")).unwrap()
}

fn hex_to_bytes(h: &str) -> Vec<u8> {
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// A legacy ("Ed", signature over the raw message) signature file.
fn legacy_sig(kp: &minisign::KeyPair) -> String {
    let sk = kp.sk.to_bytes();
    // sig_alg 2, kdf_alg 2, chk_alg 2, salt 32, ops 8, mem 8, then key id 8 and the 64-byte key
    let keynum = &sk[54..62];
    let seed = &sk[62..94];
    let sig = openssl_ed25519_sign(seed, MSG);
    let mut line2 = b"Ed".to_vec();
    line2.extend_from_slice(keynum);
    line2.extend_from_slice(&sig);
    let mut global_msg = sig.clone();
    global_msg.extend_from_slice(TRUSTED.as_bytes());
    let gsig = openssl_ed25519_sign(seed, &global_msg);
    format!(
        "untrusted comment: {UNTRUSTED}\n{}\ntrusted comment: {TRUSTED}\n{}\n",
        b64e(&line2),
        b64e(&gsig)
    )
}

fn key_line(pub_file: &str) -> String {
    pub_file.lines().nth(1).unwrap().to_string()
}

#[test]
#[ignore = "regenerates the committed vectors and the KAT block of install.sh"]
fn regenerate_vectors() {
    assert!(
        std::env::var_os("HX_KAT_REGEN").is_some(),
        "set HX_KAT_REGEN=1 to regenerate on purpose"
    );
    let dir = vectors();
    fs::create_dir_all(&dir).unwrap();
    let w = |name: &str, content: &str| fs::write(dir.join(name), content).unwrap();
    let a = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let b = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let c = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    fs::write(dir.join("msg.bin"), MSG).unwrap();
    w("key-a.pub", &pk_file(&a));
    w("key-b.pub", &pk_file(&b));
    w("key-c.pub", &pk_file(&c));
    let valid_a = sign(&a, MSG, TRUSTED);
    w("valid-a.minisig", &valid_a);
    w("valid-b.minisig", &sign(&b, MSG, TRUSTED));
    w("valid-c.minisig", &sign(&c, MSG, TRUSTED));
    w("legacy-a.minisig", &legacy_sig(&a));
    // the trusted comment altered after signing: the global signature no longer matches
    w(
        "bad-trusted-comment-a.minisig",
        &valid_a.replace("channel=stable", "channel=beta__"),
    );
    // one bit of the data signature flipped (inside the 64 signature bytes)
    let lines: Vec<&str> = valid_a.lines().collect();
    let mut raw = b64d(lines[1]);
    raw[30] ^= 1;
    w(
        "flipped-sig-a.minisig",
        &format!("{}\n{}\n{}\n{}\n", lines[0], b64e(&raw), lines[2], lines[3]),
    );
    w("crlf-a.minisig", &valid_a.replace('\n', "\r\n"));
    // correctly signed, but the trusted comment is not printable ASCII
    w(
        "nonascii-comment-a.minisig",
        &sign(&a, MSG, "hx-manifest caf\u{e9}"),
    );
    w("extra-line-a.minisig", &format!("{valid_a}extra\n"));

    // the genuinely legacy file must be accepted by the crate only with allow_legacy
    let legacy = legacy_sig(&a);
    let sb = minisign::SignatureBox::from_string(&legacy).unwrap();
    assert!(!sb.is_prehashed());
    assert!(minisign::verify(&a.pk, &sb, Cursor::new(MSG), true, false, true).is_ok());
    assert!(minisign::verify(&a.pk, &sb, Cursor::new(MSG), true, false, false).is_err());

    // the KAT block of install.sh: key A and its valid signature
    let sh = repo().join("installer/install.sh");
    let text = fs::read_to_string(&sh).unwrap();
    let (begin, end) = ("# --- KAT begin", "# --- KAT end ---");
    let i = text.find(begin).unwrap();
    let i_end = text[i..].find('\n').unwrap() + i + 1;
    let j = text.find(end).unwrap();
    let block = format!(
        "KAT_KEY='{}'\nKAT_SIG='{}'\n",
        key_line(&pk_file(&a)),
        valid_a
    );
    fs::write(&sh, format!("{}{}{}", &text[..i_end], block, &text[j..])).unwrap();
}

// ----- checks ----------------------------------------------------------------------------------

fn read(name: &str) -> String {
    fs::read_to_string(vectors().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// `installer/tests/vectors/cases.txt`: `name current next msg sig expect reason privd`.
struct Case {
    name: String,
    current: String,
    next: String,
    msg: String,
    sig: String,
    ok: bool,
    privd_same: bool,
}

fn cases() -> Vec<Case> {
    read("cases.txt")
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            assert_eq!(f.len(), 8, "{l}");
            Case {
                name: f[0].into(),
                current: f[1].into(),
                next: f[2].into(),
                msg: f[3].into(),
                sig: f[4].into(),
                ok: f[5] == "ok",
                privd_same: f[7] == "same",
            }
        })
        .collect()
}

fn key_text(token: &str) -> Option<String> {
    match token {
        "UNPROV" => None,
        "garbage" => Some("RWQnotbase64!!".to_string()),
        k => Some(read(&format!("key-{k}.pub"))),
    }
}

#[test]
fn privd_agrees_with_the_shell_on_the_shared_vectors() {
    let all = cases();
    assert!(all.len() >= 12, "the case table shrank");
    for c in all.iter().filter(|c| c.privd_same) {
        let msg = if c.msg == "msg.tampered" {
            let mut m = MSG.to_vec();
            m.push(b'x');
            m
        } else {
            fs::read(vectors().join(&c.msg)).unwrap()
        };
        let keys: Vec<String> = [&c.current, &c.next]
            .into_iter()
            .filter_map(|t| key_text(t))
            .collect();
        let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let r = UpdateKeys::from_public_keys(&refs).and_then(|k| k.verify(&msg, &read(&c.sig)));
        assert_eq!(r.is_ok(), c.ok, "case {}: privd said {r:?}", c.name);
    }
}

#[test]
fn the_committed_legacy_vector_is_really_legacy() {
    let a = read("key-a.pub");
    let sb = minisign::SignatureBox::from_string(&read("legacy-a.minisig")).unwrap();
    assert!(!sb.is_prehashed());
    let pk = minisign::PublicKey::from_base64(&key_line(&a)).unwrap();
    assert!(minisign::verify(&pk, &sb, Cursor::new(MSG), true, false, true).is_ok());
}

#[test]
fn install_sh_embeds_the_known_answer_vector() {
    let sh = fs::read_to_string(repo().join("installer/install.sh")).unwrap();
    assert!(sh.contains(&format!("KAT_KEY='{}'", key_line(&read("key-a.pub")))));
    assert!(sh.contains(&format!("KAT_SIG='{}'", read("valid-a.minisig"))));
}

/// The shell to test with: dash (what Debian and Ubuntu run as /bin/sh), else sh.
fn dash() -> &'static str {
    if Command::new("dash")
        .arg("-c")
        .arg(":")
        .status()
        .is_ok_and(|s| s.success())
    {
        "dash"
    } else {
        "sh"
    }
}

fn run_script(script: &str, args: &[&str]) {
    let out = Command::new("sh")
        .arg(repo().join(script))
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{script} failed\n--- stdout\n{}\n--- stderr\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn the_shell_suite_passes_under_dash() {
    run_script("installer/tests/run.sh", &[dash()]);
}

#[test]
fn the_handoff_suite_passes_under_dash() {
    run_script("installer/tests/handoff.sh", &[dash()]);
}
