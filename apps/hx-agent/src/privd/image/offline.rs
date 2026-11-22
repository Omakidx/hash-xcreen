//! The offline `image_file` (docs/ipc.md 6.5, "Offline `image_file`"): an image the administrator
//! placed in `/var/lib/hx/import/` together with its signed images manifest.
//!
//! Admin only, and the value is a **file name**, never a path. The directory is root-only (0700,
//! made by privd or the installer), so neither gatewayd nor a fetcher can write there (§7 rule 15
//! does not apply), but it is read with the same care as the fetcher's directory because a file
//! can still be a symlink or a hard link to something else:
//!
//! * the directory descriptor is opened `O_DIRECTORY|O_NOFOLLOW` and every file through
//!   `openat2(RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS)` with `O_NOFOLLOW|O_NONBLOCK`;
//! * each file must be a regular file with link count 1, owned by the effective uid (root), within
//!   its size limit (the image at most 4 GiB, and exactly the signed `size`);
//! * the image is copied once into the staging `O_TMPFILE`, hashing as it goes, and its SHA-256
//!   must equal the signed entry's.
//!
//! The manifest sits beside it as `images-manifest-<arch>.json` with its `.minisig`. It is verified
//! like the online one (same key, same trusted-comment rule, same validation) except that the
//! online replay counter is neither checked nor updated: an administrator may legitimately install
//! an older, still signed image offline. A timestamp more than 24 hours ahead is refused by the
//! shared validation, and an entry older than 30 days is accepted with a warning.
//!
//! After a successful import the three files are unlinked relative to the directory descriptor.

use std::sync::Arc;

use hx_ipc::privd::pb::{ErrorDetail, ProgressStage};
use hx_provision::images::{ImageEntry, MAX_IMAGE_BYTES, MAX_MANIFEST_BYTES, manifest_file_name};

use super::ImageConfig;
use crate::privd::error::CmdError;
use crate::privd::log;
use crate::privd::update::fetchdir::{FetchDir, ReadError, Staged};
use crate::privd::update::verify::digest_eq;

/// Largest signature file.
const MAX_SIG_BYTES: u64 = 16 * 1024;

fn refused(msg: impl Into<String>) -> CmdError {
    CmdError::precondition(ErrorDetail::Image, msg)
}

fn read_error(e: &ReadError) -> CmdError {
    match e {
        ReadError::Missing(n) => refused(format!("`{n}` is not in the import directory")),
        other => refused(format!("the offline file was refused: {other}")),
    }
}

/// The open import directory.
pub struct ImportDir {
    dir: Arc<FetchDir>,
    arch: String,
}

impl ImportDir {
    /// Opens the directory: a real directory (not a symlink), owned by the effective uid and not
    /// accessible to anyone else. Every file read through it must be owned by the same uid.
    pub fn open(cfg: &ImageConfig, arch: &str) -> Result<Self, CmdError> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let euid = rustix::process::geteuid().as_raw();
        let m = match std::fs::symlink_metadata(&cfg.import_dir) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(refused(
                    "there is no offline image directory (nothing was placed in /var/lib/hx/import)",
                ));
            }
            Err(e) => {
                log::error(&format!("import directory: {e}"));
                return Err(CmdError::internal(
                    "the import directory cannot be examined",
                ));
            }
        };
        if !m.is_dir() || m.uid() != euid || m.permissions().mode() & 0o077 != 0 {
            return Err(refused(
                "the import directory must be a real directory owned by root and closed to others (mode 0700)",
            ));
        }
        let dir = FetchDir::open(&cfg.import_dir).map_err(|e| {
            log::error(&format!("import directory: {e}"));
            CmdError::internal("the import directory cannot be opened")
        })?;
        Ok(Self {
            dir: Arc::new(dir.require_owner(euid)),
            arch: arch.to_string(),
        })
    }

    /// The signed manifest and its signature, as placed (not yet verified).
    pub fn manifest(&self) -> Result<(Vec<u8>, String), CmdError> {
        let name = manifest_file_name(&self.arch);
        let bytes = self
            .dir
            .read_small(&name, MAX_MANIFEST_BYTES as u64)
            .map_err(|e| read_error(&e))?;
        let sig = self
            .dir
            .read_small(&format!("{name}.minisig"), MAX_SIG_BYTES)
            .map_err(|e| read_error(&e))?;
        let sig = String::from_utf8(sig).map_err(|_| refused("the signature file is not text"))?;
        Ok((bytes, sig))
    }

    /// Copies the image file `name` once into the staging directory and checks its size and
    /// SHA-256 against the signed `entry`. Runs on a blocking thread (the file can be 4 GiB).
    pub async fn stage(
        &self,
        name: &str,
        entry: &ImageEntry,
        cfg: &ImageConfig,
    ) -> Result<Staged, CmdError> {
        if entry.size > MAX_IMAGE_BYTES {
            return Err(refused("the entry announces more than 4 GiB"));
        }
        let (dir, name, size, staging) = (
            self.dir.clone(),
            name.to_string(),
            entry.size,
            cfg.staging_dir.clone(),
        );
        let staged = tokio::task::spawn_blocking(move || dir.stage_large(&name, size, &staging))
            .await
            .map_err(|_| CmdError::internal("the copy task failed"))?
            .map_err(|e| match e {
                ReadError::Io { .. } => {
                    log::error(&format!("offline image: {e}"));
                    CmdError::internal("the offline image cannot be copied")
                        .at_stage(ProgressStage::ImageFetch)
                }
                other => read_error(&other),
            })?;
        if !digest_eq(&staged.sha256, &entry.sha256) {
            return Err(refused(
                "the offline image does not match its signed digest",
            ));
        }
        Ok(staged)
    }

    /// Unlinks the three files after a successful import (relative to the directory descriptor).
    /// Failures are returned as warnings, never errors: the desktop exists by then.
    pub fn consume(&self, name: &str) -> Vec<String> {
        let m = manifest_file_name(&self.arch);
        let mut warnings = Vec::new();
        for n in [name.to_string(), m.clone(), format!("{m}.minisig")] {
            if let Err(e) = self.dir.unlink(&n) {
                log::warn(&format!("import directory: cannot remove `{n}`: {e}"));
                warnings.push(format!(
                    "`{n}` could not be removed from /var/lib/hx/import"
                ));
            }
        }
        warnings
    }
}
