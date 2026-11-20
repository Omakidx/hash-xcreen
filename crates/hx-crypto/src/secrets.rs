//! Secrets a person handles: pairing tokens, short pairing codes, PINs (protocol §11.3, §11.4).
//!
//! All of them print as `[redacted]` in `Debug`, are zeroized on drop, and are not `Clone`.

use std::fmt;

use zeroize::Zeroizing;

use crate::{
    encoding::{CROCKFORD, base32_decode, base32_encode_into, crockford_value},
    error::{Error, Result},
    keys::random_bytes,
};

/// Prefix of a written token.
pub const TOKEN_PREFIX: &str = "hxt1-";
/// Length of a token's public id.
pub const TOKEN_ID_LEN: usize = 8;
const TOKEN_SECRET_LEN: usize = 32;
/// Symbols in a short code.
pub const CODE_LEN: usize = 8;
/// PIN length bounds, in digits.
pub const PIN_LEN: std::ops::RangeInclusive<usize> = 6..=16;

/// A long random pairing secret: an 8-byte public id and a 32-byte secret.
pub struct PairingToken {
    id: [u8; TOKEN_ID_LEN],
    secret: Zeroizing<[u8; TOKEN_SECRET_LEN]>,
}

impl PairingToken {
    /// A fresh random token.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            id: random_bytes()?,
            secret: Zeroizing::new(random_bytes()?),
        })
    }

    /// The public lookup id (sent in clear in `PairStart`).
    pub fn id(&self) -> [u8; TOKEN_ID_LEN] {
        self.id
    }

    /// The written form (`hxt1-...`), for the one-liner or the app. Handle it like a password.
    pub fn to_text(&self) -> Zeroizing<String> {
        let mut raw = Zeroizing::new([0u8; TOKEN_ID_LEN + TOKEN_SECRET_LEN]);
        raw[..TOKEN_ID_LEN].copy_from_slice(&self.id);
        raw[TOKEN_ID_LEN..].copy_from_slice(&*self.secret);
        let mut s = Zeroizing::new(String::with_capacity(TOKEN_PREFIX.len() + 64));
        s.push_str(TOKEN_PREFIX);
        base32_encode_into(&mut s, &*raw);
        s
    }

    /// Parse the written form.
    pub fn parse(text: &str) -> Result<Self> {
        let body = text
            .trim()
            .strip_prefix(TOKEN_PREFIX)
            .ok_or(Error::InvalidSecret("token"))?;
        let raw = Zeroizing::new(base32_decode(body).ok_or(Error::InvalidSecret("token"))?);
        if raw.len() != TOKEN_ID_LEN + TOKEN_SECRET_LEN {
            return Err(Error::InvalidSecret("token"));
        }
        let mut id = [0u8; TOKEN_ID_LEN];
        id.copy_from_slice(&raw[..TOKEN_ID_LEN]);
        let mut secret = Zeroizing::new([0u8; TOKEN_SECRET_LEN]);
        secret.copy_from_slice(&raw[TOKEN_ID_LEN..]);
        Ok(Self { id, secret })
    }

    /// The SPAKE2 password.
    pub(crate) fn password(&self) -> Zeroizing<Vec<u8>> {
        password_bytes(b"hx-pair-token", &*self.secret)
    }
}

impl fmt::Debug for PairingToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingToken([redacted])")
    }
}

/// A short human code: 8 symbols of the Crockford alphabet (40 bits).
pub struct PairingCode(Zeroizing<[u8; CODE_LEN]>);

impl PairingCode {
    /// A fresh random code.
    pub fn generate() -> Result<Self> {
        let mut v = Zeroizing::new(random_bytes::<CODE_LEN>()?);
        for b in v.iter_mut() {
            *b &= 31; // 32 symbols: no modulo bias
        }
        Ok(Self(v))
    }

    /// Written form `XXXX-XXXX`.
    pub fn to_text(&self) -> Zeroizing<String> {
        let mut s = Zeroizing::new(String::with_capacity(CODE_LEN + 1));
        for (i, v) in self.0.iter().enumerate() {
            if i == CODE_LEN / 2 {
                s.push('-');
            }
            s.push(char::from(CROCKFORD[usize::from(*v)]));
        }
        s
    }

    /// Parse what a person typed: case, spaces and dashes are ignored.
    pub fn parse(text: &str) -> Result<Self> {
        let mut v = Zeroizing::new([0u8; CODE_LEN]);
        let mut n = 0;
        for c in text.chars().filter(|c| !matches!(c, '-' | ' ' | '_')) {
            if n == CODE_LEN {
                return Err(Error::InvalidSecret("code"));
            }
            v[n] = crockford_value(c).ok_or(Error::InvalidSecret("code"))?;
            n += 1;
        }
        if n != CODE_LEN {
            return Err(Error::InvalidSecret("code"));
        }
        Ok(Self(v))
    }

    /// The SPAKE2 password: the normalised symbols.
    pub(crate) fn password(&self) -> Zeroizing<Vec<u8>> {
        let symbols: Zeroizing<Vec<u8>> =
            Zeroizing::new(self.0.iter().map(|v| CROCKFORD[usize::from(*v)]).collect());
        password_bytes(b"hx-pair-code", &symbols)
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingCode([redacted])")
    }
}

fn password_bytes(label: &[u8], secret: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut p = Zeroizing::new(Vec::with_capacity(label.len() + secret.len()));
    p.extend_from_slice(label);
    p.extend_from_slice(secret);
    p
}

/// What the user gives the client to pair: a token or a short code.
#[derive(Debug)]
pub enum PairingCredential {
    /// Long random token.
    Token(PairingToken),
    /// Short human code.
    Code(PairingCode),
}

impl PairingCredential {
    /// Accept either written form: `hxt1-...` is a token, anything else a code.
    pub fn parse(text: &str) -> Result<Self> {
        if text.trim().starts_with(TOKEN_PREFIX) {
            PairingToken::parse(text).map(Self::Token)
        } else {
            PairingCode::parse(text).map(Self::Code)
        }
    }
}

/// A device PIN: 6 to 16 ASCII digits.
pub struct Pin(Zeroizing<Vec<u8>>);

impl Pin {
    /// Validate what the user typed.
    pub fn new(text: &str) -> Result<Self> {
        Self::from_bytes(text.as_bytes())
    }

    /// Validate bytes received from a peer.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if !PIN_LEN.contains(&b.len()) || !b.iter().all(u8::is_ascii_digit) {
            return Err(Error::InvalidSecret("PIN"));
        }
        Ok(Self(Zeroizing::new(b.to_vec())))
    }

    /// The digits.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Pin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pin([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_text_round_trip() {
        let t = PairingToken::generate().unwrap();
        let text = t.to_text();
        assert!(text.starts_with(TOKEN_PREFIX));
        let back = PairingToken::parse(&text).unwrap();
        assert_eq!(back.id(), t.id());
        assert_eq!(*back.password(), *t.password());
        assert!(PairingToken::parse("hxt1-abc").is_err());
        assert!(PairingToken::parse("nope").is_err());
    }

    #[test]
    fn code_parses_what_people_type() {
        let c = PairingCode::generate().unwrap();
        let text = c.to_text();
        assert_eq!(text.len(), CODE_LEN + 1);
        let lower = text.to_lowercase().replace('-', " ");
        assert_eq!(
            *PairingCode::parse(&lower).unwrap().password(),
            *c.password()
        );
        assert!(PairingCode::parse("1234-567").is_err());
        assert!(PairingCode::parse("1234-56789").is_err());
        assert!(PairingCode::parse("1234-567U").is_err());
    }

    #[test]
    fn credential_dispatch() {
        let t = PairingToken::generate().unwrap();
        assert!(matches!(
            PairingCredential::parse(&t.to_text()).unwrap(),
            PairingCredential::Token(_)
        ));
        assert!(matches!(
            PairingCredential::parse("ABCD-EFGH").unwrap(),
            PairingCredential::Code(_)
        ));
    }

    #[test]
    fn pin_validation_and_redaction() {
        assert!(Pin::new("123456").is_ok());
        assert!(Pin::new("12345").is_err());
        assert!(Pin::new("12345a").is_err());
        assert!(Pin::new(&"1".repeat(17)).is_err());
        let p = Pin::new("246810").unwrap();
        assert!(!format!("{p:?}").contains("246810"));
        let t = PairingToken::generate().unwrap();
        assert!(!format!("{t:?}").contains(&t.to_text()[5..15]));
    }

    #[test]
    fn code_alphabet_is_unbiased_enough_to_be_distinct() {
        let a = PairingCode::generate().unwrap().to_text();
        let b = PairingCode::generate().unwrap().to_text();
        assert_ne!(*a, *b);
    }
}
