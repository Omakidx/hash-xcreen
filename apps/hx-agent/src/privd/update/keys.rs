//! The release signing keys embedded in the binary (architecture 5.5 and 13).
//!
//! Two minisign public keys are compiled in: the **current** key signs releases, the **next** key
//! is published in advance so that a rotation needs no flag day (a release signed by either is
//! accepted; once the next key has signed a release, the following release embeds it as current
//! and a fresh next). The files are `release-keys/current.pub` and `release-keys/next.pub`, each
//! either a minisign public key file or the word `UNPROVISIONED`. A build whose keys are all
//! unprovisioned accepts nothing: `CheckUpdate` answers `FAILED_PRECONDITION` rather than falling
//! back to any default. Installer 1E embeds the same two keys.
//!
//! Tests inject their own key through [`UpdateKeys::from_public_keys`], which exists only with
//! the `test-support` feature (a release build never has it).
//!
//! # The release gate (design D7, C12)
//!
//! - Feature `release-build` (only the release workflow enables it) makes the build fail unless
//!   **both** `CURRENT` and `NEXT` hold a key: an `UNPROVISIONED` file is a compile error, so a
//!   binary that could never verify an update, or that has no key to rotate to, cannot ship.
//! - `release-build` together with any test hook (`test-support`, `test-release-key`,
//!   `test-image-key`, `gateway-test-hooks`, `install-test-hooks`, `privd-test-hooks`) is a compile error: a release
//!   binary never carries a test hook or a test key.
//! - Feature `test-release-key` adds one more key, taken at build time from the environment
//!   variable `HX_TEST_RELEASE_PUBKEY` (the base64 key line of a test key, for example
//!   `test-release.pubkey` made by `release/make-test-release.sh`). It exists so the installer
//!   test harness can run the real binaries against a test-signed release.

use minisign_verify::{PublicKey, Signature};

use super::manifest::Manifest;
use super::verify::VerifyError;

const CURRENT: &str = include_str!("../../../release-keys/current.pub");
const NEXT: &str = include_str!("../../../release-keys/next.pub");

#[cfg(all(
    feature = "release-build",
    any(
        feature = "test-support",
        feature = "test-release-key",
        feature = "test-image-key",
        feature = "gateway-test-hooks",
        feature = "install-test-hooks",
        feature = "privd-test-hooks"
    )
))]
compile_error!(
    "feature `release-build` must not be combined with a test feature (`test-support`, \
     `test-release-key`, `test-image-key`, `gateway-test-hooks`, `install-test-hooks`, \
     `privd-test-hooks`): \
     a release binary carries no test hook and no test key"
);

/// A test key injected at build time (`test-release-key` only).
#[cfg(feature = "test-release-key")]
const TEST_KEY: Option<&str> = option_env!("HX_TEST_RELEASE_PUBKEY");

/// `const` substring search (the gate below runs at compile time).
#[cfg_attr(not(any(test, feature = "release-build")), allow(dead_code))]
const fn contains(hay: &str, needle: &str) -> bool {
    let (h, n) = (hay.as_bytes(), needle.as_bytes());
    if n.len() > h.len() {
        return false;
    }
    let mut i = 0;
    while i + n.len() <= h.len() {
        let mut j = 0;
        while j < n.len() && h[i + j] == n[j] {
            j += 1;
        }
        if j == n.len() {
            return true;
        }
        i += 1;
    }
    false
}

/// A key file that carries a key: no `UNPROVISIONED` marker and a minisign key line (`RW`, the
/// base64 start of the `Ed` algorithm bytes) somewhere in it.
#[cfg_attr(not(any(test, feature = "release-build")), allow(dead_code))]
pub(crate) const fn provisioned(text: &str) -> bool {
    !contains(text, "UNPROVISIONED") && contains(text, "RW")
}

#[cfg(feature = "release-build")]
const _: () = {
    assert!(
        provisioned(CURRENT),
        "release-build: apps/hx-agent/release-keys/current.pub is UNPROVISIONED"
    );
    assert!(
        provisioned(NEXT),
        "release-build: apps/hx-agent/release-keys/next.pub is UNPROVISIONED"
    );
};

/// The keys a release signature is checked against.
#[derive(Clone)]
pub struct UpdateKeys {
    keys: Vec<PublicKey>,
}

/// The base64 key line of a minisign public key file, or `None` for `UNPROVISIONED` and anything
/// that holds no key line.
pub(crate) fn key_line(text: &str) -> Option<&str> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("untrusted comment:"))?;
    (line != "UNPROVISIONED").then_some(line)
}

pub(crate) fn parse_key(text: &str) -> Option<PublicKey> {
    PublicKey::from_base64(key_line(text)?).ok()
}

impl UpdateKeys {
    /// The keys compiled into this binary (the unprovisioned or malformed ones are left out).
    pub fn embedded() -> Self {
        let keys: Vec<PublicKey> = [CURRENT, NEXT].into_iter().filter_map(parse_key).collect();
        #[cfg(feature = "test-release-key")]
        let keys = {
            let mut keys = keys;
            keys.extend(TEST_KEY.and_then(parse_key));
            keys
        };
        Self { keys }
    }

    /// True when no key is available: every update is refused.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// How many keys are present.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Keys from minisign public key text (the `.pub` file or its base64 line). Test-only.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_public_keys(keys: &[&str]) -> Result<Self, VerifyError> {
        let keys = keys
            .iter()
            .map(|k| parse_key(k).ok_or(VerifyError::BadKey))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { keys })
    }

    /// Verifies `sig_text` (a `.minisig` file) over exactly `data` against each embedded key.
    /// Only prehashed signatures (`ED`, what minisign writes by default) are accepted; the
    /// legacy form is refused. The trusted comment's global signature is checked too.
    ///
    /// This checks the signature only. A release manifest goes through
    /// [`verify_manifest`](Self::verify_manifest), which also binds the signed trusted comment to
    /// the manifest.
    pub fn verify(&self, data: &[u8], sig_text: &str) -> Result<(), VerifyError> {
        self.verify_signed(data, sig_text).map(|_| ())
    }

    /// [`verify`](Self::verify), returning the signed trusted comment.
    pub fn verify_signed(&self, data: &[u8], sig_text: &str) -> Result<String, VerifyError> {
        if self.keys.is_empty() {
            return Err(VerifyError::NoKeys);
        }
        let sig = Signature::decode(sig_text).map_err(|_| VerifyError::BadSignatureFile)?;
        for k in &self.keys {
            if k.verify(data, &sig, false).is_ok() {
                return Ok(sig.trusted_comment().to_string());
            }
        }
        Err(VerifyError::SignatureMismatch)
    }

    /// Verifies the signature of release manifest bytes **and** that its signed trusted comment is
    /// exactly the one the release workflow writes for that manifest
    /// (`hx-manifest v<version> channel=<channel> arch=<arch>`, see
    /// [`Manifest::trusted_comment`]): a signature made over these bytes for another purpose (the
    /// installer script's `hx-install.sh v<V>`, an image manifest, a test) is not a release
    /// signature. Returns the parsed manifest, whose fields still need
    /// [`Manifest::check`].
    pub fn verify_manifest(&self, data: &[u8], sig_text: &str) -> Result<Manifest, VerifyError> {
        let comment = self.verify_signed(data, sig_text)?;
        let m = Manifest::parse(data).map_err(|_| VerifyError::BadManifest)?;
        if comment != m.trusted_comment() {
            return Err(VerifyError::BadComment);
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_key_files_are_a_key_or_unprovisioned() {
        for (name, text) in [("current", CURRENT), ("next", NEXT)] {
            match key_line(text) {
                None => assert!(text.contains("UNPROVISIONED"), "{name}"),
                Some(_) => assert!(parse_key(text).is_some(), "{name} is not a valid key"),
            }
        }
    }

    #[test]
    fn the_provisioned_gate_tells_a_key_from_the_placeholder() {
        assert!(!provisioned("UNPROVISIONED\n"));
        assert!(!provisioned("# note\nUNPROVISIONED\n"));
        assert!(!provisioned(""));
        assert!(provisioned(
            "untrusted comment: minisign public key: X\nRWQabcdefgh\n"
        ));
        assert!(contains("abcdef", "cde") && !contains("abc", "abcd") && contains("a", "a"));
    }

    #[test]
    fn the_const_gate_agrees_with_the_runtime_parser_on_the_shipped_files() {
        for text in [CURRENT, NEXT] {
            if provisioned(text) {
                assert!(parse_key(text).is_some(), "a provisioned file must parse");
            } else {
                assert!(key_line(text).is_none());
            }
        }
    }

    /// Run with `HX_TEST_RELEASE_PUBKEY="$(cat <dir>/test-release.pubkey)" cargo test -p hx-agent
    /// --features test-release-key --lib privd::update::keys` (release/make-test-release.sh).
    #[cfg(feature = "test-release-key")]
    #[test]
    fn the_test_key_is_embedded_when_given_at_build_time() {
        let before = [CURRENT, NEXT].into_iter().filter_map(parse_key).count();
        match TEST_KEY {
            Some(k) => {
                assert!(
                    parse_key(k).is_some(),
                    "HX_TEST_RELEASE_PUBKEY is not a key"
                );
                assert_eq!(UpdateKeys::embedded().len(), before + 1);
            }
            None => assert_eq!(UpdateKeys::embedded().len(), before),
        }
    }

    #[test]
    fn a_build_without_keys_verifies_nothing() {
        let none = UpdateKeys { keys: Vec::new() };
        assert!(none.is_empty());
        assert_eq!(none.verify(b"x", "y"), Err(VerifyError::NoKeys));
    }

    #[test]
    fn key_files_are_parsed_leniently_but_garbage_is_not_a_key() {
        assert!(key_line("UNPROVISIONED\n").is_none());
        assert!(key_line("# note\nUNPROVISIONED\n").is_none());
        assert_eq!(
            key_line("untrusted comment: x\nRWQabc\n").unwrap(),
            "RWQabc"
        );
        assert!(parse_key("RWQnotbase64!!").is_none());
        assert!(parse_key("").is_none());
    }
}
