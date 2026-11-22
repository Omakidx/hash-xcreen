//! Importing a verified image into Incus, the `hx-img-*` aliases, reuse and deletion
//! (docs/ipc.md 6.5, "Image import, caching and cleanup").
//!
//! * The staged file is sent with `Client::import_image` (`POST /1.0/images`, streamed from the
//!   anonymous staging file); privd **requires** the fingerprint Incus reports to equal the signed
//!   SHA-256 (the client checks it). A real Incus 6.0.0 answers a duplicate import with HTTP 500
//!   "already exists", so `get_image` is asked first.
//! * Every imported image gets the alias `hx-img-<recipe>-<first 12 hex of the fingerprint>`, which
//!   is what `Client::delete_image` insists on before it deletes anything: an image the
//!   administrator imported is never touched.
//! * A record goes into `images-state` **before** the import starts, so a crash leaves a record to
//!   clean up, never an unrecorded image.
//! * The image is kept until `ready` (a retried `CreateDesktop` skips the download when the
//!   fingerprint is still the selected entry and the record is at most 7 days old), then deleted;
//!   at the start of `CreateDesktop` and in `Uninstall` (both modes) every recorded image that is
//!   not selected is deleted.

use std::time::Duration;

use hx_provision::images::ImageEntry;
use hx_provision::incus::{Client, IMAGE_ALIAS_PREFIX, ImageUpload, IncusError, Transport};

use super::fetch::ImgErr;
use super::state::{CACHE_MAX_AGE_SECS, CachedImage, ImagesState};
use crate::privd::daemon::Daemon;
use crate::privd::error::CmdError;
use crate::privd::log;
use crate::privd::update::fetchdir::Staged;

/// The alias of an imported image.
pub fn alias_for(recipe: &str, fingerprint: &str) -> String {
    format!(
        "{IMAGE_ALIAS_PREFIX}{recipe}-{}",
        &fingerprint[..fingerprint.len().min(12)]
    )
}

impl<T: Transport + Clone + 'static> Daemon<T> {
    /// Reads `images-state`.
    pub(crate) fn read_images_state(&self) -> Result<ImagesState, CmdError> {
        let _g = self
            .image_state_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        ImagesState::load(&self.store).map_err(|e| {
            log::error(&format!("images-state: {e}"));
            CmdError::internal("privd's image state cannot be read")
        })
    }

    /// Changes `images-state` under the gate that serialises the read-decide-write of concurrent
    /// commands (`CreateDesktop` and `Uninstall`), and saves it.
    pub(crate) fn update_images_state<R>(
        &self,
        f: impl FnOnce(&mut ImagesState) -> R,
    ) -> Result<R, CmdError> {
        let _g = self
            .image_state_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut st = ImagesState::load(&self.store).map_err(|e| {
            log::error(&format!("images-state: {e}"));
            CmdError::internal("privd's image state cannot be read")
        })?;
        let before = st.clone();
        let r = f(&mut st);
        if st != before {
            st.save(&self.store).map_err(|e| {
                log::error(&format!("images-state: {e}"));
                CmdError::internal("privd's image state cannot be saved")
            })?;
        }
        Ok(r)
    }
}

/// Whether `entry`'s image is already in Incus and recorded as imported by privd at most 7 days
/// ago (a retried `CreateDesktop` skips the download).
pub async fn find_cached<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    client: &Client<T>,
    entry: &ImageEntry,
) -> Result<bool, CmdError> {
    let st = d.read_images_state()?;
    let Some(rec) = st.find(&entry.sha256) else {
        return Ok(false);
    };
    if d.now().saturating_sub(rec.imported_unix) > CACHE_MAX_AGE_SECS {
        return Ok(false);
    }
    Ok(client.get_image(&entry.sha256).await?.is_some())
}

/// Imports the staged, verified file (unless Incus already has the image) and aliases it. The
/// record is written first. `Err` carries the failing stage's error.
pub async fn import<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    client: &Client<T>,
    entry: &ImageEntry,
    staged: Staged,
    deadline: Duration,
) -> Result<(), CmdError> {
    let fp = entry.sha256.clone();
    d.update_images_state(|s| {
        s.insert(CachedImage {
            fingerprint: fp.clone(),
            recipe: entry.recipe.clone(),
            build_id: entry.build_id.clone(),
            imported_unix: d.now(),
        });
    })?;
    if client.get_image(&fp).await?.is_none() {
        let got = client
            .import_image(
                ImageUpload {
                    file: staged.file,
                    len: staged.len,
                    fingerprint: fp.clone(),
                },
                deadline,
            )
            .await?;
        if got != fp {
            return Err(CmdError::internal(
                "Incus stored the image under another fingerprint",
            ));
        }
    }
    ensure_alias(client, &entry.recipe, &fp).await?;
    Ok(())
}

/// Makes sure the image carries a `hx-img-` alias (an already existing alias is fine).
pub async fn ensure_alias<T: Transport + Clone + 'static>(
    client: &Client<T>,
    recipe: &str,
    fingerprint: &str,
) -> Result<(), CmdError> {
    let alias = alias_for(recipe, fingerprint);
    match client.create_image_alias(&alias, fingerprint).await {
        Ok(()) => Ok(()),
        Err(IncusError::Api { code: 409, .. }) => Ok(()),
        // A real Incus has answered an existing alias with other codes too: the image says.
        Err(e) => match client.get_image(fingerprint).await {
            Ok(Some(img)) if img.aliases.iter().any(|a| a == &alias) => Ok(()),
            _ => Err(e.into()),
        },
    }
}

/// Deletes the image `fingerprint` from Incus and forgets its record. An image that has lost its
/// alias (a crash between import and alias) is aliased first, because deleting without our alias
/// is refused. `true` when nothing of ours is left afterwards.
pub async fn purge<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    client: &Client<T>,
    fingerprint: &str,
) -> bool {
    let recipe = d
        .read_images_state()
        .ok()
        .and_then(|s| s.find(fingerprint).map(|c| c.recipe.clone()))
        .unwrap_or_else(|| "image".to_string());
    let removed = async {
        let Some(img) = client.get_image(fingerprint).await? else {
            return Ok::<_, IncusError>(true);
        };
        if !img
            .aliases
            .iter()
            .any(|a| a.starts_with(IMAGE_ALIAS_PREFIX))
        {
            // Only an image privd recorded is ever aliased and deleted here.
            let recorded = d
                .read_images_state()
                .ok()
                .is_some_and(|s| s.find(fingerprint).is_some());
            if !recorded {
                return Ok(false);
            }
            client
                .create_image_alias(&alias_for(&recipe, fingerprint), fingerprint)
                .await?;
        }
        client.delete_image(fingerprint).await?;
        Ok(true)
    }
    .await;
    match removed {
        Ok(true) => {
            let _ = d.update_images_state(|s| s.remove(fingerprint));
            true
        }
        Ok(false) => {
            // Not ours (no record, no alias): forget nothing, delete nothing.
            false
        }
        Err(e) => {
            log::warn(&format!(
                "cannot delete image {}: {e}",
                &fingerprint[..12.min(fingerprint.len())]
            ));
            false
        }
    }
}

/// Deletes every recorded image except `keep`. Returns the fingerprints that were removed.
pub async fn cleanup_unselected<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    client: &Client<T>,
    keep: Option<&str>,
) -> Vec<String> {
    let Ok(st) = d.read_images_state() else {
        return Vec::new();
    };
    let mut gone = Vec::new();
    for c in st
        .cached
        .iter()
        .filter(|c| Some(c.fingerprint.as_str()) != keep)
    {
        if purge(d, client, &c.fingerprint).await {
            gone.push(c.fingerprint.clone());
        }
    }
    gone
}

/// An image fetch error as the command error of its stage (shared by the callers).
pub fn img_error(e: ImgErr, stage: hx_ipc::privd::pb::ProgressStage) -> CmdError {
    e.into_cmd(stage)
}
