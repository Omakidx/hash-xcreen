//! The secrets of one `install.sh --ssh` run (design C2, docs/ipc.md section 5.4).
//!
//! ```text
//! "HXI1" | { kind u8 | len u16 LE | bytes[len] }* | kind 0, len 0
//! 1 USER_PASSWORD     1..=511 bytes, no \r \n NUL     required
//! 2 PIN               6..=16 ASCII digits             required
//! 3 PAIRING_TOKEN     hxt1-..., at most 1024 bytes    optional
//! 4 OWNER_PUBLIC_KEY  32 bytes                        optional
//! ```
//!
//! The values are checked here with the same rules as the installer's parser (a bad value is
//! refused before anything is sent) and encoded into one `Zeroizing` buffer sized up front, so no
//! reallocation leaves a copy behind. Nothing here is `Clone`, `Display` or logged.
//!
//! The encoder is written from the contract; `tests/frames_roundtrip.rs` feeds its output to the
//! server-side parser (`hx_agent::install::stdin::read_frames`).

use std::fmt;

use zeroize::Zeroizing;

use crate::error::{Result, SshSetupError};

/// The magic.
pub const MAGIC: &[u8; 4] = b"HXI1";
/// Most bytes of the whole stream.
pub const MAX_TOTAL: usize = 8192;
/// Longest user password (libxcrypt reads at most 511 bytes).
pub const MAX_PASSWORD: usize = 511;

/// Record kinds.
pub mod kind {
    /// The Linux password of the desktop user.
    pub const PASSWORD: u8 = 1;
    /// The PIN.
    pub const PIN: u8 = 2;
    /// The app's own pairing token.
    pub const TOKEN: u8 = 3;
    /// The owner public key.
    pub const OWNER_KEY: u8 = 4;
}

/// Everything secret that one install run needs. Supplied again for every run (a resume
/// included): nothing is stored.
pub struct Secrets {
    user_password: Zeroizing<String>,
    pin: Zeroizing<String>,
    pairing_token: Option<Zeroizing<String>>,
    owner_key: Option<[u8; 32]>,
    sudo_password: Option<Zeroizing<String>>,
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secrets")
            .field("user_password", &"<redacted>")
            .field("pin", &"<redacted>")
            .field("pairing_token", &self.pairing_token.is_some())
            .field("owner_key", &self.owner_key.is_some())
            .field("sudo_password", &self.sudo_password.is_some())
            .finish()
    }
}

fn invalid(m: &str) -> SshSetupError {
    SshSetupError::InvalidInput(m.to_owned())
}

/// Checks a desktop-user password against the installer's rule.
pub fn check_password(pw: &str) -> Result<()> {
    let b = pw.as_bytes();
    if b.is_empty() || b.iter().any(|c| matches!(c, 0 | b'\n' | b'\r')) {
        return Err(invalid(
            "a password is 1 to 511 bytes with no newline, carriage return or NUL",
        ));
    }
    if b.len() > MAX_PASSWORD {
        return Err(invalid(
            "the password is longer than 511 bytes, which the password checker cannot handle",
        ));
    }
    Ok(())
}

/// Checks a PIN: 6 to 16 ASCII digits.
pub fn check_pin(pin: &str) -> Result<()> {
    let b = pin.as_bytes();
    if !(6..=16).contains(&b.len()) || !b.iter().all(u8::is_ascii_digit) {
        return Err(invalid("a PIN is 6 to 16 digits"));
    }
    Ok(())
}

impl Secrets {
    /// The required secrets.
    pub fn new(user_password: Zeroizing<String>, pin: Zeroizing<String>) -> Result<Self> {
        check_password(&user_password)?;
        check_pin(&pin)?;
        Ok(Self {
            user_password,
            pin,
            pairing_token: None,
            owner_key: None,
            sudo_password: None,
        })
    }

    /// The app's own pairing token (`hxt1-...`), so it can pair right after the install.
    pub fn with_pairing_token(mut self, token: Zeroizing<String>) -> Result<Self> {
        if token.len() > 1024 || hx_crypto::PairingToken::parse(&token).is_err() {
            return Err(invalid("that is not a pairing token (expected hxt1-...)"));
        }
        self.pairing_token = Some(token);
        Ok(self)
    }

    /// The owner public key to enrol (Ed25519, 32 bytes).
    pub fn with_owner_key(mut self, key: [u8; 32]) -> Self {
        self.owner_key = Some(key);
        self
    }

    /// The password `sudo` asks for on the server (usually the SSH account's own). Only used
    /// when the account is not root and sudo is not passwordless. A value with a line break or
    /// NUL is refused.
    pub fn with_sudo_password(mut self, pw: Zeroizing<String>) -> Result<Self> {
        check_password(&pw).map_err(|_| invalid("the sudo password has a line break or NUL"))?;
        self.sudo_password = Some(pw);
        Ok(self)
    }

    /// The sudo password, if one was given.
    pub fn sudo_password(&self) -> Option<&str> {
        self.sudo_password.as_deref().map(String::as_str)
    }

    /// The C2 stream: magic, records, end record.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let records: [(u8, Option<&[u8]>); 4] = [
            (kind::PASSWORD, Some(self.user_password.as_bytes())),
            (kind::PIN, Some(self.pin.as_bytes())),
            (
                kind::TOKEN,
                self.pairing_token.as_ref().map(|t| t.as_bytes()),
            ),
            (kind::OWNER_KEY, self.owner_key.as_ref().map(|k| &k[..])),
        ];
        let total: usize = MAGIC.len()
            + records
                .iter()
                .filter_map(|(_, v)| v.map(|v| 3 + v.len()))
                .sum::<usize>()
            + 3;
        if total > MAX_TOTAL {
            return Err(invalid("the secrets are larger than 8192 bytes"));
        }
        let mut out = Zeroizing::new(Vec::with_capacity(total));
        out.extend_from_slice(MAGIC);
        for (k, v) in records {
            let Some(v) = v else { continue };
            let len = u16::try_from(v.len()).map_err(|_| invalid("a record is too long"))?;
            out.push(k);
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(v);
        }
        out.extend_from_slice(&[0, 0, 0]);
        debug_assert_eq!(out.len(), total);
        Ok(out)
    }

    /// What goes to the remote stdin: the sudo password line first when `with_sudo` (sudo
    /// consumes it), then the C2 stream.
    pub(crate) fn stdin_stream(&self, with_sudo: bool) -> Result<Zeroizing<Vec<u8>>> {
        let frames = self.encode()?;
        if !with_sudo {
            return Ok(frames);
        }
        let pw = self
            .sudo_password
            .as_ref()
            .ok_or(SshSetupError::SudoPasswordRequired)?;
        let mut out = Zeroizing::new(Vec::with_capacity(pw.len() + 1 + frames.len()));
        out.extend_from_slice(pw.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(&frames);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn z(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_owned())
    }

    #[test]
    fn layout_matches_the_contract() {
        let s = Secrets::new(z("pw"), z("123456")).unwrap();
        let e = s.encode().unwrap();
        assert_eq!(&e[..4], b"HXI1");
        assert_eq!(&e[4..9], &[1, 2, 0, b'p', b'w']);
        assert_eq!(&e[9..18], &[2, 6, 0, b'1', b'2', b'3', b'4', b'5', b'6']);
        assert_eq!(&e[e.len() - 3..], &[0, 0, 0]);
        assert_eq!(e.len(), 4 + 5 + 9 + 3);
    }

    #[test]
    fn bad_values_are_refused_before_anything_is_sent() {
        assert!(Secrets::new(z(""), z("123456")).is_err());
        assert!(Secrets::new(z("a\nb"), z("123456")).is_err());
        assert!(Secrets::new(z("a\0b"), z("123456")).is_err());
        assert!(Secrets::new(z(&"x".repeat(512)), z("123456")).is_err());
        assert!(Secrets::new(z(&"x".repeat(511)), z("123456")).is_ok());
        assert!(Secrets::new(z("pw"), z("12345")).is_err());
        assert!(Secrets::new(z("pw"), z("1234567890123456")).is_ok());
        assert!(Secrets::new(z("pw"), z("12345678901234567")).is_err());
        assert!(Secrets::new(z("pw"), z("12345a")).is_err());
        let s = Secrets::new(z("pw"), z("123456")).unwrap();
        assert!(s.with_pairing_token(z("nope")).is_err());
    }

    #[test]
    fn sudo_password_comes_first_and_only_when_asked() {
        let s = Secrets::new(z("pw"), z("123456"))
            .unwrap()
            .with_sudo_password(z("sudo-pw"))
            .unwrap();
        let with = s.stdin_stream(true).unwrap();
        assert!(with.starts_with(b"sudo-pw\nHXI1"));
        let without = s.stdin_stream(false).unwrap();
        assert!(without.starts_with(b"HXI1"));
        let none = Secrets::new(z("pw"), z("123456")).unwrap();
        assert!(matches!(
            none.stdin_stream(true),
            Err(SshSetupError::SudoPasswordRequired)
        ));
    }

    #[test]
    fn debug_never_prints_a_secret() {
        let s = Secrets::new(z("hunter2-secret"), z("987654")).unwrap();
        let d = format!("{s:?}");
        assert!(!d.contains("hunter2") && !d.contains("987654"));
    }
}
