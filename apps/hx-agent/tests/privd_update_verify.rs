//! Signatures, keys and versions of the update path (docs/ipc.md 6.12 rule 1 and 7 rule 10):
//! a valid signature, an altered manifest, the wrong key, key rotation, the legacy and the
//! malformed signature files, that a build embeds no test key, and a fuzz of the strict version
//! syntax against an independent matcher.

mod privd_update_common;

use hx_agent::privd::update::keys::UpdateKeys;
use hx_agent::privd::update::verify::{VerifyError, digest_eq, sha256_hex};
use hx_agent::privd::update::version::Version;
use privd_update_common::Signer;

const DATA: &[u8] = b"{\"schema\":1,\"version\":\"1.4.2\"}";

fn keys(of: &[&Signer]) -> UpdateKeys {
    let texts: Vec<String> = of.iter().map(|s| s.public()).collect();
    UpdateKeys::from_public_keys(&texts.iter().map(String::as_str).collect::<Vec<_>>()).unwrap()
}

#[test]
fn a_valid_signature_verifies_and_anything_else_does_not() {
    let s = Signer::new();
    let k = keys(&[&s]);
    let sig = s.sign(DATA);
    assert_eq!(k.verify(DATA, &sig), Ok(()));
    // One byte of the data, one byte of the signature.
    let mut data = DATA.to_vec();
    data[10] ^= 1;
    assert_eq!(k.verify(&data, &sig), Err(VerifyError::SignatureMismatch));
    assert_eq!(k.verify(b"", &sig), Err(VerifyError::SignatureMismatch));
    // The trusted comment is covered by the global signature.
    let forged = sig.replace("hx test release", "hx forged release");
    assert_ne!(forged, sig);
    assert_eq!(k.verify(DATA, &forged), Err(VerifyError::SignatureMismatch));
    // Malformed signature files.
    for junk in [
        "",
        "x",
        "untrusted comment: only\n",
        &sig[..sig.len() / 2],
        &sig.replace('\n', " "),
    ] {
        assert!(k.verify(DATA, junk).is_err(), "{junk:?}");
    }
}

#[test]
fn a_signature_from_another_key_is_refused() {
    let (good, other) = (Signer::new(), Signer::new());
    let sig = other.sign(DATA);
    assert_eq!(
        keys(&[&good]).verify(DATA, &sig),
        Err(VerifyError::SignatureMismatch)
    );
    // Even when the other key is embedded as well, its signature is accepted: that is the
    // meaning of "embedded", and nothing else is.
    assert_eq!(keys(&[&good, &other]).verify(DATA, &sig), Ok(()));
}

#[test]
fn current_and_next_keys_both_verify_and_rotation_retires_the_old_one() {
    let (current, next) = (Signer::new(), Signer::new());
    let both = keys(&[&current, &next]);
    assert_eq!(both.len(), 2);
    assert_eq!(both.verify(DATA, &current.sign(DATA)), Ok(()));
    assert_eq!(both.verify(DATA, &next.sign(DATA)), Ok(()));
    // After the rotation the binary embeds {next, newer}: the old current key no longer verifies.
    let newer = Signer::new();
    let rotated = keys(&[&next, &newer]);
    assert_eq!(rotated.verify(DATA, &next.sign(DATA)), Ok(()));
    assert_eq!(rotated.verify(DATA, &newer.sign(DATA)), Ok(()));
    assert_eq!(
        rotated.verify(DATA, &current.sign(DATA)),
        Err(VerifyError::SignatureMismatch)
    );
}

#[test]
fn a_minisign_public_key_file_with_comments_is_accepted_as_a_key() {
    let s = Signer::new();
    let file = format!("untrusted comment: minisign public key\n{}\n", s.public());
    let k = UpdateKeys::from_public_keys(&[&file]).unwrap();
    assert_eq!(k.verify(DATA, &s.sign(DATA)), Ok(()));
    assert!(UpdateKeys::from_public_keys(&["RWQ-not-a-key"]).is_err());
    assert!(UpdateKeys::from_public_keys(&["UNPROVISIONED"]).is_err());
}

#[test]
fn a_build_embeds_no_test_key() {
    // The compiled-in keys of this build are the committed `release-keys/*.pub`; a key generated
    // by a test cannot be among them.
    let embedded = UpdateKeys::embedded();
    let s = Signer::new();
    assert_eq!(
        embedded.verify(DATA, &s.sign(DATA)),
        Err(match embedded.is_empty() {
            true => VerifyError::NoKeys,
            false => VerifyError::SignatureMismatch,
        })
    );
}

#[test]
fn sha256_comparison_is_exact() {
    let d = sha256_hex(b"artifact");
    assert!(digest_eq(&d, &d));
    let mut other = d.clone().into_bytes();
    other[63] = if other[63] == b'0' { b'1' } else { b'0' };
    assert!(!digest_eq(&d, std::str::from_utf8(&other).unwrap()));
    assert!(!digest_eq(&d, &d[..63]));
    assert!(!digest_eq(&d, &d.to_uppercase()));
}

// ----- the strict version syntax ----------------------------------------------------------------

/// `^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-(alpha|beta|rc)\.[0-9]{1,4})?$`, matched by hand and
/// independently of `hx_ipc::privd::is_valid_update_version` (no `split`, no `parse`).
fn reference(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    let digits = |i: &mut usize| -> bool {
        let start = *i;
        while *i < b.len() && b[*i].is_ascii_digit() && *i - start < 5 {
            *i += 1;
        }
        (1..=4).contains(&(*i - start))
    };
    for n in 0..3 {
        if !digits(&mut i) {
            return false;
        }
        if n < 2 {
            if b.get(i) != Some(&b'.') {
                return false;
            }
            i += 1;
        }
    }
    if i == b.len() {
        return true;
    }
    if b.get(i) != Some(&b'-') {
        return false;
    }
    i += 1;
    let rest = &s[i..];
    let tag_len = ["alpha", "beta", "rc"]
        .iter()
        .find(|t| rest.starts_with(*t))
        .map(|t| t.len());
    let Some(t) = tag_len else { return false };
    i += t;
    if b.get(i) != Some(&b'.') {
        return false;
    }
    i += 1;
    digits(&mut i) && i == b.len()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[(self.next() % v.len() as u64) as usize]
    }
}

#[test]
fn the_version_syntax_agrees_with_an_independent_matcher_on_many_inputs() {
    let atoms = [
        "0",
        "1",
        "9",
        "12",
        "123",
        "1234",
        "12345",
        "00",
        "0000",
        ".",
        ".",
        ".",
        "-",
        "-",
        "alpha",
        "beta",
        "rc",
        "gamma",
        "+",
        " ",
        "\n",
        "\0",
        "v",
        "/",
        "..",
        "٣",
        "１",
        "e",
        "x",
        "_",
        "1.2.3",
        "1.2.3-rc.1",
        "1.2.3-",
        "-rc.1",
    ];
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut matched = 0;
    for _ in 0..300_000 {
        let n = 1 + (rng.next() % 9) as usize;
        let s: String = (0..n).map(|_| *rng.pick(&atoms)).collect();
        let ours = hx_ipc::privd::is_valid_update_version(&s);
        assert_eq!(ours, reference(&s), "{s:?}");
        assert_eq!(Version::parse(&s).is_some(), ours, "{s:?}");
        matched += usize::from(ours);
    }
    assert!(
        matched > 100,
        "the generator reached valid versions ({matched})"
    );
    // Hand-picked traps: a trailing newline (the `$` of many regex engines), leading zeros are
    // fine (the pattern allows them), five digits are not, unicode digits are not digits.
    for (s, valid) in [
        ("1.2.3", true),
        ("1.2.3\n", false),
        ("\n1.2.3", false),
        ("01.002.0003", true),
        ("12345.0.0", false),
        ("1.2.3-rc.1", true),
        ("1.2.3-RC.1", false),
        ("1.2.3-rc.12345", false),
        ("1.2.3-rc.1.1", false),
        ("1.2.3-alpha", false),
        ("1.2.3+build", false),
        ("1.2.3 ", false),
        ("1.2.٣", false),
        ("1.2.3\0", false),
        ("../1.2.3", false),
        ("1.2.3/..", false),
        ("", false),
    ] {
        assert_eq!(hx_ipc::privd::is_valid_update_version(s), valid, "{s:?}");
        assert_eq!(reference(s), valid, "{s:?}");
    }
}
