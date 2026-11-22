//! Signature checks shared by `verify` and `manifest` (which verifies the previous manifest).
//!
//! The same rules as `hx-privd` applies to an images manifest: a prehashed minisign signature
//! (the minisign default; the legacy form is refused), the trusted comment's global signature, and,
//! as defence in depth, a trusted comment that names this manifest:
//! `hx-images-manifest schema=1 arch=<arch> timestamp=<T>`, with `T` equal to the manifest's own
//! timestamp. Signing itself is done by the minisign CLI in the `image-signing` job.

use std::path::Path;

use hx_provision::images::ImagesManifest;
use minisign_verify::{PublicKey, Signature};

use crate::util::{CliError, read_bounded, refused};

/// Prefix of the trusted comment of every images manifest signature.
pub const COMMENT_PREFIX: &str = "hx-images-manifest ";

/// The trusted comment `T` must carry for a manifest of `arch` and `timestamp`.
pub fn trusted_comment(arch: &str, timestamp: u64) -> String {
    format!("{COMMENT_PREFIX}schema=1 arch={arch} timestamp={timestamp}")
}

/// The base64 key line of a minisign public key file (or a bare key line), or `None` for
/// `UNPROVISIONED` and anything without a key.
fn key_line(text: &str) -> Option<&str> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("untrusted comment:"))?;
    (line != "UNPROVISIONED").then_some(line)
}

/// Load minisign public keys from files. A file that holds `UNPROVISIONED` or no key is an error.
pub fn load_keys(paths: &[String]) -> Result<Vec<PublicKey>, CliError> {
    paths
        .iter()
        .map(|p| {
            let text = read_bounded(Path::new(p), 4096)?;
            let text = String::from_utf8_lossy(&text);
            let line = key_line(&text).ok_or_else(|| {
                refused(format!(
                    "{p} holds no public key (UNPROVISIONED or empty): nothing can be verified"
                ))
            })?;
            PublicKey::from_base64(line)
                .map_err(|e| refused(format!("{p} is not a minisign public key: {e}")))
        })
        .collect()
}

/// Verify `sig_text` over exactly `data` against any of `keys`, and return the trusted comment.
pub fn verify_signature(
    data: &[u8],
    sig_text: &str,
    keys: &[PublicKey],
) -> Result<String, CliError> {
    if keys.is_empty() {
        return Err(refused("no public key to verify with"));
    }
    let sig = Signature::decode(sig_text)
        .map_err(|e| refused(format!("the signature file is not valid: {e}")))?;
    for k in keys {
        // `false`: no legacy (non-prehashed) signatures.
        if k.verify(data, &sig, false).is_ok() {
            return Ok(sig.trusted_comment().to_string());
        }
    }
    Err(refused(
        "the signature does not verify against any of the public keys (or is not prehashed)",
    ))
}

/// Verify a manifest file and its signature: the signature, the trusted comment (which must name
/// this manifest's arch and timestamp), and the manifest's own rules for `arch` at time `now`.
/// Returns the parsed manifest.
pub fn verify_manifest(
    manifest: &Path,
    sig: &Path,
    keys: &[PublicKey],
    arch: &str,
    now: u64,
) -> Result<ImagesManifest, CliError> {
    let bytes = read_bounded(manifest, hx_provision::images::MAX_MANIFEST_BYTES as u64)?;
    let sig_bytes = read_bounded(sig, 4096)?;
    let sig_text =
        std::str::from_utf8(&sig_bytes).map_err(|_| refused("the signature file is not text"))?;
    let comment = verify_signature(&bytes, sig_text, keys)?;
    let m = ImagesManifest::parse(&bytes).map_err(|e| refused(e.to_string()))?;
    let want = trusted_comment(arch, m.timestamp);
    if comment != want {
        return Err(refused(format!(
            "the signature's trusted comment is not `{want}`"
        )));
    }
    m.validate(arch, now).map_err(|e| refused(e.to_string()))?;
    Ok(m)
}
