//! Small, total text encodings used for identifiers, stored secrets and what users type.

/// Lowercase hexadecimal.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    s
}

/// Hexadecimal (either case) to bytes; `None` on odd length or a non-hex character.
pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.as_chunks::<2>()
        .0
        .iter()
        .map(|p| Some((nibble(p[0])? << 4) | nibble(p[1])?))
        .collect()
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// RFC 4648 base32, lowercase, no padding.
#[cfg(test)]
pub(crate) fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    base32_encode_into(&mut out, bytes);
    out
}

/// Append the base32 form of `bytes` to `out` (no intermediate copy of secret material).
pub(crate) fn base32_encode_into(out: &mut String, bytes: &[u8]) {
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((acc >> bits) & 31) as usize]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(B32[((acc << (5 - bits)) & 31) as usize]));
    }
}

/// Inverse of [`base32_encode`]. Case-insensitive; `None` for any other character, for a
/// length that no byte string encodes to, or for non-zero trailing bits.
pub(crate) fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c.to_ascii_lowercase() {
            c @ b'a'..=b'z' => c - b'a',
            c @ b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if bits >= 5 || acc != 0 {
        return None;
    }
    Some(out)
}

/// The 32 symbols of the Crockford alphabet (no `I`, `L`, `O`, `U`).
pub(crate) const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Index of a user-typed Crockford symbol (case-insensitive; `O` reads as `0`, `I` and `L` as `1`).
pub(crate) fn crockford_value(c: char) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    CROCKFORD
        .iter()
        .position(|&s| char::from(s) == c)
        .and_then(|i| u8::try_from(i).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let v: Vec<u8> = (0..=255).collect();
        assert_eq!(hex_decode(&hex_encode(&v)), Some(v));
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("zz"), None);
    }

    #[test]
    fn base32_matches_rfc4648_vectors() {
        assert_eq!(base32_encode(b"foobar"), "mzxw6ytboi");
        assert_eq!(base32_encode(b"fo"), "mzxq");
        assert_eq!(base32_decode("MZXW6YTBOI"), Some(b"foobar".to_vec()));
    }

    #[test]
    fn base32_round_trip_and_rejects() {
        for n in 0..40 {
            let v: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(base32_decode(&base32_encode(&v)), Some(v));
        }
        assert_eq!(base32_decode("mzxq1"), None);
        // Non-canonical trailing bits.
        assert_eq!(base32_decode("mzxr"), None);
        assert_eq!(base32_decode("m"), None);
    }

    #[test]
    fn crockford_aliases() {
        assert_eq!(crockford_value('o'), Some(0));
        assert_eq!(crockford_value('l'), Some(1));
        assert_eq!(crockford_value('U'), None);
        assert_eq!(crockford_value('z'), Some(31));
    }
}
