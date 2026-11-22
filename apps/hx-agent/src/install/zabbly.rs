//! The Zabbly Incus repository (design D4): a third-party apt source, used only when the distro's
//! Incus is too old (below 6.0.0, or below 6.0.5 with `--docker`) or absent.
//!
//! * The signing key is **embedded** (`zabbly-key.asc`) and its OpenPGP v4 fingerprint is
//!   **pinned** here. Before the key is written the installer computes the fingerprint of the
//!   embedded key and refuses to go on if it differs.
//! * The pinned fingerprint is the one the Zabbly project publishes in its own repository
//!   (<https://github.com/zabbly/incus>, "GPG fingerprint"): `4EFC 5906 96CB 15B8 7C73 A3AD
//!   82CC 8797 C838 DCFD`. It was checked there for this change, not typed from memory.
//! * **The key file is not provisioned in this change** (it reads `UNPROVISIONED`): the maintainer
//!   drops `key.asc` from <https://pkgs.zabbly.com/key.asc> into `zabbly-key.asc` and verifies the
//!   fingerprint against the page above. Until then a host that needs Zabbly fails the `incus`
//!   stage with a clear message and a distro-Incus host is unaffected.
//! * The source is a deb822 file with `Signed-By` pointing at this one key, so no other key can
//!   sign for it.

use super::error::{InstallError, Result};

/// The pinned fingerprint of the Zabbly signing key (40 upper-case hex characters).
pub const FINGERPRINT: &str = "4EFC590696CB15B87C73A3AD82CC8797C838DCFD";

/// The repository.
pub const URI: &str = "https://pkgs.zabbly.com/incus/lts-6.0";

/// The suites Zabbly publishes for the supported hosts (Ubuntu 24.04 and 26.04, Debian 12 and 13).
pub const SUITES: &[&str] = &["noble", "resolute", "bookworm", "trixie"];

const KEY_FILE: &str = include_str!("zabbly-key.asc");

/// The embedded key, or `None` while it is not provisioned.
pub fn embedded_key() -> Option<&'static str> {
    let t = KEY_FILE.trim_start();
    if t.starts_with("UNPROVISIONED") || !t.contains("BEGIN PGP PUBLIC KEY BLOCK") {
        None
    } else {
        Some(KEY_FILE)
    }
}

/// The deb822 source for `suite`.
pub fn sources_text(suite: &str, keyring: &str) -> String {
    format!(
        "# Written by hx-agent install. Zabbly Incus LTS 6.0 (third party); signed by the pinned key only.\n\
         Enabled: yes\n\
         Types: deb\n\
         URIs: {URI}\n\
         Suites: {suite}\n\
         Components: main\n\
         Architectures: amd64\n\
         Signed-By: {keyring}\n"
    )
}

// ----- the fingerprint ------------------------------------------------------------------------

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        acc = (acc << 6) | u32::from(b64_value(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// The binary packets of an ASCII-armored block.
fn dearmor(text: &str) -> Option<Vec<u8>> {
    let mut lines = text.lines().map(str::trim);
    lines.find(|l| l.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"))?;
    // Armor headers end at the first blank line.
    for l in lines.by_ref() {
        if l.is_empty() {
            break;
        }
    }
    let mut body = String::new();
    for l in lines {
        if l.starts_with("-----END") {
            return base64_decode(&body);
        }
        // The CRC-24 line.
        if l.starts_with('=') {
            continue;
        }
        body.push_str(l);
    }
    None
}

/// SHA-1 (RFC 3174). Used only to compute an OpenPGP v4 fingerprint, which is defined as SHA-1;
/// it is not used for any security decision about new data.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, b) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// The v4 fingerprint (40 upper-case hex) of the primary key of an armored public key block.
pub fn fingerprint(armored: &str) -> Option<String> {
    let bin = dearmor(armored)?;
    let first = *bin.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let (tag, len, hdr): (u8, usize, usize) = if first & 0x40 != 0 {
        // New format.
        let o1 = usize::from(*bin.get(1)?);
        let (len, n) = match o1 {
            0..=191 => (o1, 1),
            192..=223 => (((o1 - 192) << 8) + usize::from(*bin.get(2)?) + 192, 2),
            255 => (
                u32::from_be_bytes([*bin.get(2)?, *bin.get(3)?, *bin.get(4)?, *bin.get(5)?])
                    as usize,
                5,
            ),
            _ => return None,
        };
        (first & 0x3f, len, 1 + n)
    } else {
        match first & 3 {
            0 => (((first >> 2) & 0xf), usize::from(*bin.get(1)?), 2),
            1 => (
                (first >> 2) & 0xf,
                usize::from(u16::from_be_bytes([*bin.get(1)?, *bin.get(2)?])),
                3,
            ),
            2 => (
                (first >> 2) & 0xf,
                u32::from_be_bytes([*bin.get(1)?, *bin.get(2)?, *bin.get(3)?, *bin.get(4)?])
                    as usize,
                5,
            ),
            _ => return None,
        }
    };
    if tag != 6 {
        return None;
    }
    let body = bin.get(hdr..hdr.checked_add(len)?)?;
    if body.first() != Some(&4) {
        return None;
    }
    let mut m = vec![0x99u8];
    m.extend_from_slice(&u16::try_from(len).ok()?.to_be_bytes());
    m.extend_from_slice(body);
    Some(
        sha1(&m)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>(),
    )
}

/// The embedded key, checked against the pinned fingerprint.
pub fn verified_key() -> Result<&'static str> {
    let key = embedded_key().ok_or_else(|| {
        InstallError::preflight(
            "this host needs Incus from the Zabbly repository, but this hx-agent build embeds no Zabbly key (zabbly-key.asc is not provisioned); install Incus 6.0.5 or newer yourself and run again",
        )
    })?;
    match fingerprint(key) {
        Some(fp) if fp == FINGERPRINT => Ok(key),
        _ => Err(InstallError::verify(
            "the embedded Zabbly key does not have the pinned fingerprint; refusing to add the repository",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_known_answers() {
        let hex = |d: [u8; 20]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex(sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(hex(sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
    }

    fn armor(b64: &str) -> String {
        format!(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: test\n\n{b64}\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"
        )
    }

    #[test]
    fn the_fingerprint_of_old_and_new_format_packets() {
        // Synthetic v4 key packets; the expected value is SHA-1 over 0x99 || length || body,
        // computed independently with Python's hashlib.
        let want = "D4E48857F888F1286083808B6FD4B826F99C9907";
        assert_eq!(
            fingerprint(&armor("mQANBGVT8QABABCrzQAIAw==")).unwrap(),
            want
        );
        assert_eq!(fingerprint(&armor("xg0EZVPxAAEAEKvNAAgD")).unwrap(), want);
    }

    #[test]
    fn garbage_is_not_a_key() {
        assert!(fingerprint("nothing").is_none());
        assert!(fingerprint(&armor("AAAA")).is_none());
        // A v3 key packet or a non-key packet.
        assert!(fingerprint(&armor("mQANA2VT8QABABCrzQAIAw==")).is_none());
    }

    #[test]
    fn the_pinned_fingerprint_is_well_formed() {
        assert_eq!(FINGERPRINT.len(), 40);
        assert!(
            FINGERPRINT
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_lowercase())
        );
    }

    #[test]
    fn the_embedded_key_matches_the_pinned_fingerprint() {
        match embedded_key() {
            // Not provisioned yet: the maintainer's step (reported); nothing to check.
            None => assert!(verified_key().is_err()),
            Some(k) => assert_eq!(fingerprint(k).as_deref(), Some(FINGERPRINT)),
        }
    }

    #[test]
    fn the_source_names_one_key_and_one_suite() {
        let s = sources_text("noble", "/etc/apt/keyrings/hx-zabbly.asc");
        assert!(s.contains("Suites: noble\n"));
        assert!(s.contains("Signed-By: /etc/apt/keyrings/hx-zabbly.asc\n"));
        assert!(s.contains("URIs: https://pkgs.zabbly.com/incus/lts-6.0\n"));
    }
}
