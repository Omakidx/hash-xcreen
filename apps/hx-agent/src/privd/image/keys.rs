//! The desktop-image signing keys embedded in the binary (docs/ipc.md 6.12, "Images manifest").
//!
//! A **separate** minisign key pair from the release keys (`image-keys/{current,next}.pub`, each a
//! minisign public key file or the word `UNPROVISIONED`): its secret half lives in the GitHub
//! environment `image-signing`, restricted to `main` with no per-run approval (a weekly job
//! signs), so a leaked image key must never be able to sign an agent release, which is root on the
//! host. A build whose keys are all unprovisioned accepts no image: `auto` builds on the server
//! (`NO_IMAGE_KEY`) and `prebuilt` fails `FAILED_PRECONDITION`.
//!
//! On top of the signature privd requires the **trusted comment** to start with
//! `hx-images-manifest ` (the signature check itself ignores what the comment says), as defence in
//! depth: a signature made over these bytes for another purpose does not pass.
//!
//! # The release gate
//!
//! - Feature `release-build` makes the build fail unless **both** key files hold a key, next to the
//!   same gate for the release keys (`privd::update::keys`): the maintainer decided (wave 2, Q2)
//!   that a release must not ship while the image keys are `UNPROVISIONED`, because that release
//!   could never use a prebuilt image until it updates.
//! - `release-build` together with `test-image-key` (or any other test feature, see the release
//!   keys) is a compile error.
//! - Feature `test-image-key` adds one more key from the build-time environment variable
//!   `HX_TEST_IMAGE_PUBKEY` (the base64 key line of a test key), so the installer VM tests and the
//!   image CI can run the real binaries against a test-signed image. It exists only in test builds.

use minisign_verify::{PublicKey, Signature};

use crate::privd::update::keys::parse_key;

const CURRENT: &str = include_str!("../../../image-keys/current.pub");
const NEXT: &str = include_str!("../../../image-keys/next.pub");

/// What the trusted comment of a signed images manifest starts with.
pub const TRUSTED_COMMENT_PREFIX: &str = "hx-images-manifest ";

#[cfg(all(feature = "release-build", feature = "test-image-key"))]
compile_error!(
    "feature `release-build` must not be combined with `test-image-key`: a release binary \
     carries no test key"
);

#[cfg(feature = "release-build")]
const _: () = {
    assert!(
        crate::privd::update::keys::provisioned(CURRENT),
        "release-build: apps/hx-agent/image-keys/current.pub is UNPROVISIONED"
    );
    assert!(
        crate::privd::update::keys::provisioned(NEXT),
        "release-build: apps/hx-agent/image-keys/next.pub is UNPROVISIONED"
    );
};

/// A test key injected at build time (`test-image-key` only).
#[cfg(feature = "test-image-key")]
const TEST_KEY: Option<&str> = option_env!("HX_TEST_IMAGE_PUBKEY");

/// Why an images manifest signature was refused. None of these carry attacker-controlled text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ImageVerifyError {
    /// This build embeds no image key.
    #[error("this build embeds no image signing key")]
    NoKeys,
    /// The signature file is not a minisign signature.
    #[error("the signature file is not a minisign signature")]
    BadSignatureFile,
    /// No embedded key validates the signature (wrong key, altered data, legacy signature).
    #[error("no embedded image key validates the signature")]
    SignatureMismatch,
    /// The signature is valid but its trusted comment is not an images manifest's.
    #[error("the signed trusted comment is not an images manifest's")]
    BadComment,
    /// A key could not be parsed (tests).
    #[error("malformed public key")]
    BadKey,
}

/// The keys an images manifest signature is checked against.
#[derive(Clone)]
pub struct ImageKeys {
    keys: Vec<PublicKey>,
}

impl ImageKeys {
    /// The keys compiled into this binary (unprovisioned or malformed ones are left out).
    pub fn embedded() -> Self {
        let keys: Vec<PublicKey> = [CURRENT, NEXT].into_iter().filter_map(parse_key).collect();
        #[cfg(feature = "test-image-key")]
        let keys = {
            let mut keys = keys;
            keys.extend(TEST_KEY.and_then(parse_key));
            keys
        };
        Self { keys }
    }

    /// No key at all: no image is ever accepted.
    pub fn none() -> Self {
        Self { keys: Vec::new() }
    }

    /// True when no key is available.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// How many keys are present.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Keys from minisign public key text (the `.pub` file or its base64 line). Test-only.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_public_keys(keys: &[&str]) -> Result<Self, ImageVerifyError> {
        let keys = keys
            .iter()
            .map(|k| parse_key(k).ok_or(ImageVerifyError::BadKey))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { keys })
    }

    /// Verifies `sig_text` (a `.minisig` file) over exactly `manifest`: a prehashed signature by an
    /// embedded key (the legacy form is refused; the trusted comment's global signature is checked
    /// too) whose trusted comment starts with [`TRUSTED_COMMENT_PREFIX`].
    pub fn verify_manifest(&self, manifest: &[u8], sig_text: &str) -> Result<(), ImageVerifyError> {
        if self.keys.is_empty() {
            return Err(ImageVerifyError::NoKeys);
        }
        let sig = Signature::decode(sig_text).map_err(|_| ImageVerifyError::BadSignatureFile)?;
        for k in &self.keys {
            if k.verify(manifest, &sig, false).is_ok() {
                return if sig.trusted_comment().starts_with(TRUSTED_COMMENT_PREFIX) {
                    Ok(())
                } else {
                    Err(ImageVerifyError::BadComment)
                };
            }
        }
        Err(ImageVerifyError::SignatureMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privd::update::keys::{key_line, provisioned};

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
    fn the_const_gate_agrees_with_the_runtime_parser_on_the_shipped_files() {
        for text in [CURRENT, NEXT] {
            if provisioned(text) {
                assert!(parse_key(text).is_some(), "a provisioned file must parse");
            } else {
                assert!(key_line(text).is_none());
            }
        }
    }

    #[test]
    fn the_image_keys_are_not_the_release_keys() {
        // The two pairs must never be the same files, or a leaked image key could sign a release.
        let release = [
            include_str!("../../../release-keys/current.pub"),
            include_str!("../../../release-keys/next.pub"),
        ];
        for img in [CURRENT, NEXT] {
            if let Some(l) = key_line(img) {
                assert!(
                    !release.iter().any(|r| key_line(r) == Some(l)),
                    "an image key equals a release key"
                );
            }
        }
    }

    #[test]
    fn a_build_without_keys_verifies_nothing() {
        let none = ImageKeys::none();
        assert!(none.is_empty());
        assert_eq!(
            none.verify_manifest(b"x", "y"),
            Err(ImageVerifyError::NoKeys)
        );
    }

    #[test]
    fn garbage_is_not_a_signature() {
        let keys = ImageKeys {
            keys: vec![
                PublicKey::from_base64("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3")
                    .unwrap(),
            ],
        };
        assert_eq!(
            keys.verify_manifest(b"x", "not a signature"),
            Err(ImageVerifyError::BadSignatureFile)
        );
    }

    /// Run with `HX_TEST_IMAGE_PUBKEY="<base64 key line>" cargo test -p hx-agent --features
    /// test-image-key --lib privd::image::keys`.
    #[cfg(feature = "test-image-key")]
    #[test]
    fn the_test_key_is_embedded_when_given_at_build_time() {
        let before = [CURRENT, NEXT].into_iter().filter_map(parse_key).count();
        match TEST_KEY {
            Some(k) => {
                assert!(parse_key(k).is_some(), "HX_TEST_IMAGE_PUBKEY is not a key");
                assert_eq!(ImageKeys::embedded().len(), before + 1);
            }
            None => assert_eq!(ImageKeys::embedded().len(), before),
        }
    }
}
