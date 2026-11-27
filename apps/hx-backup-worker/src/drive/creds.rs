//! The two inputs of the Drive helper that are not the link: the fixed OAuth client and the user's
//! refresh token (ipc.md §29 a and b).
//!
//! * The **client** (`/usr/lib/hx/current/drive-client.json`) is not confidential (an installed-app
//!   secret is public by Google's own rule); it still never reaches a log or an error text.
//! * The **token** (`$CREDENTIALS_DIRECTORY/drive-token`, `{"refresh_token": "..."}`) is the secret:
//!   read into zeroizing buffers, never logged, never in an error.
//!
//! Every error here is a fixed text: it names the rule, never the content.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use zeroize::Zeroizing;

/// Where the release ships the client file (ipc.md §29 a).
pub const CLIENT_FILE: &str = "/usr/lib/hx/current/drive-client.json";
/// The credential's name under `$CREDENTIALS_DIRECTORY` (`LoadCredentialEncrypted=drive-token:...`).
pub const TOKEN_CREDENTIAL: &str = "drive-token";
/// Largest client file.
pub const MAX_CLIENT_FILE_BYTES: usize = 4096;
/// Largest token credential.
pub const MAX_TOKEN_FILE_BYTES: usize = 2048;

/// Why a credential is unusable. The text never carries content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredsError {
    /// The file does not exist.
    #[error("file not found")]
    Missing,
    /// It exists but cannot be read.
    #[error("file not readable")]
    Unreadable,
    /// It is larger than the cap.
    #[error("file too large")]
    TooLarge,
    /// Not the documented format.
    #[error("{0}")]
    Invalid(&'static str),
}

fn read_capped(path: &Path, cap: usize) -> Result<Zeroizing<Vec<u8>>, CredsError> {
    let f = File::open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => CredsError::Missing,
        _ => CredsError::Unreadable,
    })?;
    let mut buf = Zeroizing::new(Vec::with_capacity(cap + 1));
    f.take(cap as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|_| CredsError::Unreadable)?;
    if buf.len() > cap {
        return Err(CredsError::TooLarge);
    }
    Ok(buf)
}

/// The fixed OAuth client of every install.
#[derive(Clone)]
pub struct ClientConfig {
    client_id: String,
    client_secret: Zeroizing<String>,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig").finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawClient {
    client_id: String,
    client_secret: String,
}

fn printable_ascii(s: &str) -> bool {
    (1..=256).contains(&s.len()) && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

impl ClientConfig {
    /// Parses the client file's content.
    ///
    /// # Errors
    /// [`CredsError::Invalid`] unless it is exactly `{"client_id", "client_secret"}`, each 1 to 256
    /// bytes of printable ASCII.
    pub fn parse(bytes: &[u8]) -> Result<Self, CredsError> {
        let raw: RawClient = serde_json::from_slice(bytes)
            .map_err(|_| CredsError::Invalid("not the documented JSON object"))?;
        let secret = Zeroizing::new(raw.client_secret);
        if !printable_ascii(&raw.client_id) {
            return Err(CredsError::Invalid(
                "client_id: 1 to 256 printable ASCII bytes",
            ));
        }
        if !printable_ascii(&secret) {
            return Err(CredsError::Invalid(
                "client_secret: 1 to 256 printable ASCII bytes",
            ));
        }
        Ok(Self {
            client_id: raw.client_id,
            client_secret: secret,
        })
    }

    /// Reads and parses the client file.
    ///
    /// # Errors
    /// [`CredsError`]; the caller exits with 75 (ipc.md §24).
    pub fn load(path: &Path) -> Result<Self, CredsError> {
        Self::parse(&read_capped(path, MAX_CLIENT_FILE_BYTES)?)
    }

    pub(crate) fn id(&self) -> &str {
        &self.client_id
    }

    pub(crate) fn secret(&self) -> &str {
        &self.client_secret
    }
}

/// The user's refresh token.
#[derive(Clone)]
pub struct Token(Zeroizing<String>);

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(..)")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawToken {
    refresh_token: String,
}

impl Token {
    /// Parses the credential's content.
    ///
    /// # Errors
    /// [`CredsError::Invalid`] unless it is exactly `{"refresh_token": "..."}` with 16 to 1 024
    /// bytes of `[A-Za-z0-9._~/+=-]`.
    pub fn parse(bytes: &[u8]) -> Result<Self, CredsError> {
        let raw: RawToken = serde_json::from_slice(bytes)
            .map_err(|_| CredsError::Invalid("not the documented JSON object"))?;
        let t = Zeroizing::new(raw.refresh_token);
        let ok = (16..=1024).contains(&t.len())
            && t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._~/+=-".contains(&b));
        if !ok {
            return Err(CredsError::Invalid(
                "refresh_token: not the documented shape",
            ));
        }
        Ok(Self(t))
    }

    /// Reads `drive-token` from `credentials_directory` (systemd's `$CREDENTIALS_DIRECTORY`).
    ///
    /// # Errors
    /// [`CredsError`]; the session then answers every `OpenRepo` with `AUTH_REVOKED`.
    pub fn load(credentials_directory: Option<&Path>) -> Result<Self, CredsError> {
        let dir = credentials_directory.ok_or(CredsError::Missing)?;
        if !dir.is_absolute() {
            return Err(CredsError::Invalid("credentials directory is not absolute"));
        }
        Self::parse(&read_capped(
            &dir.join(TOKEN_CREDENTIAL),
            MAX_TOKEN_FILE_BYTES,
        )?)
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

/// `$CREDENTIALS_DIRECTORY`, as systemd sets it for the service.
#[must_use]
pub fn credentials_directory_from_env() -> Option<PathBuf> {
    std::env::var_os("CREDENTIALS_DIRECTORY")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_file_has_exactly_two_keys() {
        let ok = br#"{"client_id":"1234-abc.apps.example","client_secret":"fake-secret-value"}"#;
        assert!(ClientConfig::parse(ok).is_ok());
        for bad in [
            &br#"{"client_id":"a"}"#[..],
            br#"{"client_id":"a","client_secret":"b","x":1}"#,
            br#"{"client_id":"","client_secret":"b"}"#,
            br#"{"client_id":"a b","client_secret":"b"}"#,
            br#"{"client_id":"a","client_secret":"b\n"}"#,
            br#"[]"#,
            b"",
        ] {
            assert!(ClientConfig::parse(bad).is_err(), "{bad:?}");
        }
        let long = format!(
            r#"{{"client_id":"{}","client_secret":"b"}}"#,
            "a".repeat(257)
        );
        assert!(ClientConfig::parse(long.as_bytes()).is_err());
    }

    #[test]
    fn the_token_credential_has_exactly_one_key_of_the_documented_shape() {
        let ok = br#"{"refresh_token":"1//fake-refresh-token_value"}"#;
        assert!(Token::parse(ok).is_ok());
        for bad in [
            &br#"{"refresh_token":"short"}"#[..],
            br#"{"refresh_token":"1//fake-refresh-token_value","client_id":"x"}"#,
            br#"{"refresh_token":"has space in it here ok"}"#,
            br#"{"refresh_token":"quote\"quote\"quote\"quote"}"#,
            br#"{}"#,
            b"1//fake-refresh-token_value",
        ] {
            assert!(Token::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn debug_output_and_errors_never_carry_the_values() {
        let c = ClientConfig::parse(
            br#"{"client_id":"visible-id-1","client_secret":"hidden-secret-1"}"#,
        )
        .unwrap();
        let t = Token::parse(br#"{"refresh_token":"hidden-refresh-token-1"}"#).unwrap();
        for text in [format!("{c:?}"), format!("{t:?}")] {
            assert!(!text.contains("hidden"), "{text}");
            assert!(!text.contains("visible"), "{text}");
        }
        let e = ClientConfig::parse(br#"{"client_id":"hidden-id","client_secret":"a b"}"#)
            .unwrap_err()
            .to_string();
        assert!(!e.contains("hidden"), "{e}");
    }

    #[test]
    fn files_are_capped_and_missing_is_distinct() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            ClientConfig::load(&dir.path().join("none")).unwrap_err(),
            CredsError::Missing
        );
        let big = dir.path().join("big");
        std::fs::write(&big, vec![b' '; MAX_CLIENT_FILE_BYTES + 1]).unwrap();
        assert_eq!(ClientConfig::load(&big).unwrap_err(), CredsError::TooLarge);
        assert_eq!(Token::load(None).unwrap_err(), CredsError::Missing);
        assert_eq!(
            Token::load(Some(dir.path())).unwrap_err(),
            CredsError::Missing
        );
        assert!(matches!(
            Token::load(Some(Path::new("relative"))),
            Err(CredsError::Invalid(_))
        ));
        std::fs::write(
            dir.path().join(TOKEN_CREDENTIAL),
            br#"{"refresh_token":"1//fake-refresh-token_value"}"#,
        )
        .unwrap();
        assert!(Token::load(Some(dir.path())).is_ok());
    }
}
