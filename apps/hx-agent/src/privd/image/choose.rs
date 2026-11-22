//! `privd::image::choose`: the algorithm of docs/ipc.md 6.5 step 3 (architecture 4.3), with a
//! reason code and a fixed-template reason string for every outcome.
//!
//! ```text
//!  1  BUILD                                   -> build        BUILD_REQUESTED
//!  2  image_file                              -> offline path, any failure is an error (IMAGE_FILE)
//!  3  no image key embedded                   -> auto: build  NO_IMAGE_KEY        | prebuilt: FAILED_PRECONDITION (IMAGE)
//!  4  images-manifest job fails               -> auto: build  LIST_UNAVAILABLE    | prebuilt: UNAVAILABLE
//!  5  signature, comment, schema, timestamp   -> auto: build  LIST_UNVERIFIED     | prebuilt: FAILED_PRECONDITION (IMAGE)
//!  6  no entry for (recipe, digest, agent)    -> build        NO_MATCHING_IMAGE
//!  7  entry older than 30 days                -> build        IMAGE_STALE
//!  8  a cached image matches                  -> skip the download, still check the pool (9)
//!  9  disk (statvfs)                          -> auto: build  DISK                | prebuilt: FAILED_PRECONDITION (POOL)
//! 10  auto only: speed probe (at most 30 s)   -> PROBE_FAILED | DOWNLOAD_TOO_SLOW | SLOWER_THAN_MIRROR | PREBUILT_FASTER
//! ```
//!
//! `PREBUILT` skips the probe (`PREBUILT_REQUESTED`) and fails instead of building at 3 to 7 and 9.
//! The fetch of the prebuilt image and its fall back to a build are `cmd::create`'s.
//!
//! The digest an entry must carry is that of the recipe **embedded in this agent**
//! (`Plan::build_digest()` of `Catalog::resolve(id, &[])`): compatibility is bound by content, not
//! by date.

use hx_ipc::privd::pb::{self, ErrorDetail, ImageReason, ProgressStage};
use hx_ipc::text::sanitize_text;
use hx_provision::RecipeId;
use hx_provision::images::{ImageEntry, ImagesManifest, MAX_AGE_SECS, recipe_name};
use hx_provision::incus::{Client, Transport};

use super::fetch::{Fetch, ImgErr, ProbeResult};
use super::keys::ImageKeys;
use super::offline::ImportDir;
use super::{GIB, cache};
use crate::fetcher::ImageJob;
use crate::privd::daemon::{Ctx, Daemon};
use crate::privd::error::CmdError;
use crate::privd::log;
use crate::privd::probe::ImageSpace;

/// A download that would take longer than this is not worth it (S / release rate).
pub const MAX_DOWNLOAD_SECS: u64 = 900;
/// The release host must be at least this fraction of the mirror's speed (1/2).
pub const MIRROR_RATIO_NUM: u128 = 1;
/// See [`MIRROR_RATIO_NUM`].
pub const MIRROR_RATIO_DEN: u128 = 2;
/// Headroom on the pool beyond the unpacked size.
pub const POOL_HEADROOM: u64 = 8 * GIB;
/// Headroom beyond the image size on the staging and Incus file systems.
pub const COPY_HEADROOM: u64 = GIB;

/// What the caller asked for.
pub struct Request<'a> {
    /// `image_mode` of the request.
    pub mode: pb::ImageMode,
    /// The offline file name (Admin only, already validated).
    pub image_file: Option<&'a str>,
    /// The recipe.
    pub recipe: RecipeId,
    /// `(total, free)` bytes of the pool.
    pub pool: (u64, u64),
}

/// An outcome and the words for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    /// The machine-readable code.
    pub code: ImageReason,
    /// A fixed template with numbers only, at most 256 bytes, sanitized.
    pub text: String,
}

impl Reason {
    /// A reason with `text` sanitized and cut to 256 bytes.
    pub fn new(code: ImageReason, text: impl AsRef<str>) -> Self {
        Self {
            code,
            text: sanitize_text(text.as_ref(), 256),
        }
    }
}

/// Where the bytes come from.
pub enum Source {
    /// The image fetcher.
    Online,
    /// The administrator's file in `/var/lib/hx/import/`.
    Offline {
        /// The open import directory.
        dir: ImportDir,
        /// The file name.
        name: String,
    },
}

/// A prebuilt image the algorithm settled on.
pub struct Selected {
    /// The signed entry.
    pub entry: ImageEntry,
    /// Where the bytes come from.
    pub source: Source,
    /// The image is already in Incus: no download or import.
    pub cached: bool,
    /// Measured by the probe, bytes per second.
    pub release_bps: Option<u64>,
    /// Measured by the probe, bytes per second.
    pub mirror_bps: Option<u64>,
    /// Notes for the result's `warnings` (an old offline image).
    pub warnings: Vec<String>,
}

/// The decision.
pub enum Decision {
    /// Build on the server.
    Build(Reason),
    /// Install from this image.
    Prebuilt(Box<Selected>, Reason),
}

impl Decision {
    /// The reason.
    pub fn reason(&self) -> &Reason {
        match self {
            Self::Build(r) | Self::Prebuilt(_, r) => r,
        }
    }
}

/// `4.1` for 4.1 GiB (one decimal, no floating point).
pub fn gib_text(bytes: u64) -> String {
    let tenths = u128::from(bytes) * 10 / u128::from(GIB);
    format!("{}.{}", tenths / 10, tenths % 10)
}

/// `38.2` for 38.2 MiB/s.
pub fn mibs_text(bps: u64) -> String {
    let tenths = u128::from(bps) * 10 / (1024 * 1024);
    format!("{}.{}", tenths / 10, tenths % 10)
}

fn age_text(age_secs: u64) -> String {
    match age_secs / 86_400 {
        0 => "less than a day old".to_string(),
        1 => "1 day old".to_string(),
        n => format!("{n} days old"),
    }
}

/// What the free space leaves short.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Short {
    /// Bytes needed.
    pub need: u64,
    /// Bytes free.
    pub free: u64,
    /// Where (a path or `the storage pool`).
    pub on: &'static str,
}

/// The disk rule (ipc.md 6.5 step 7): with S the image size and U its unpacked size, the file
/// system of `/var/lib/hx` needs S + 1 GiB (staging), the one of `/var/lib/incus` S + 1 GiB
/// (Incus's copy), or 2S + 2 GiB when both are one device; the pool needs U + 8 GiB and the 15%
/// rule. A cached image needs the pool part only. Space that cannot be read fails closed.
pub fn check_disk(
    space: Option<ImageSpace>,
    pool: (u64, u64),
    s: u64,
    u: u64,
    cached: bool,
) -> Result<(), Short> {
    if !cached {
        let Some(sp) = space else {
            return Err(Short {
                need: s.saturating_add(COPY_HEADROOM),
                free: 0,
                on: "/var/lib",
            });
        };
        if sp.same_device {
            let need = s.saturating_mul(2).saturating_add(2 * COPY_HEADROOM);
            if sp.state_free < need {
                return Err(Short {
                    need,
                    free: sp.state_free,
                    on: "/var/lib",
                });
            }
        } else {
            let need = s.saturating_add(COPY_HEADROOM);
            if sp.state_free < need {
                return Err(Short {
                    need,
                    free: sp.state_free,
                    on: "/var/lib/hx",
                });
            }
            if sp.incus_free < need {
                return Err(Short {
                    need,
                    free: sp.incus_free,
                    on: "/var/lib/incus",
                });
            }
        }
    }
    let (total, free) = pool;
    let need_pool = u.saturating_add(POOL_HEADROOM);
    let need = need_pool.max(total / 100 * 15);
    if free < need_pool || free.saturating_mul(100) < total.saturating_mul(15) {
        return Err(Short {
            need,
            free,
            on: "the storage pool",
        });
    }
    Ok(())
}

/// What the speed probe means for the choice (ipc.md 6.5 step 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Download the image.
    Prebuilt,
    /// The release host could not be measured.
    ProbeFailed,
    /// The download would take longer than 900 s; the estimate in seconds.
    TooSlow(u64),
    /// The release host is under half the mirror's speed.
    SlowerThanMirror,
}

/// The decision of step 8, for an image of `size` bytes. A failed mirror probe alone still allows
/// the prebuilt image, because a build would suffer from the same network.
pub fn verdict(size: u64, p: &ProbeResult) -> Verdict {
    let Some(r) = p.release_bps else {
        return Verdict::ProbeFailed;
    };
    if r == 0 || u128::from(size) > u128::from(MAX_DOWNLOAD_SECS) * u128::from(r) {
        return Verdict::TooSlow(size.checked_div(r).unwrap_or(u64::MAX));
    }
    if let Some(m) = p.mirror_bps
        && u128::from(r) * MIRROR_RATIO_DEN < u128::from(m) * MIRROR_RATIO_NUM
    {
        return Verdict::SlowerThanMirror;
    }
    Verdict::Prebuilt
}

/// Checks a manifest in full: the signature (with the trusted-comment rule), the document, its
/// rules for this host and clock. The replay counter is the caller's. `Err` is a short text for
/// the audit log, never the fetcher's bytes verbatim.
pub fn verify_manifest(
    keys: &ImageKeys,
    bytes: &[u8],
    sig: &str,
    arch: &str,
    now: u64,
) -> Result<ImagesManifest, String> {
    keys.verify_manifest(bytes, sig)
        .map_err(|e| e.to_string())?;
    let m = ImagesManifest::parse(bytes).map_err(|e| sanitize_text(&e.to_string(), 160))?;
    m.validate(arch, now)
        .map_err(|e| sanitize_text(&e.to_string(), 160))?;
    Ok(m)
}

fn refused(msg: impl Into<String>) -> CmdError {
    CmdError::precondition(ErrorDetail::Image, msg)
}

/// A build outcome in `auto` and the error the same outcome is in `prebuilt` mode.
fn fall(auto: bool, code: ImageReason, text: &str, err: CmdError) -> Result<Decision, CmdError> {
    if auto {
        Ok(Decision::Build(Reason::new(code, text)))
    } else {
        Err(err)
    }
}

fn build(code: ImageReason, text: &str) -> Result<Decision, CmdError> {
    Ok(Decision::Build(Reason::new(code, text)))
}

/// The days-old text and the reason of a chosen image.
fn chosen_reason(
    code: ImageReason,
    entry: &ImageEntry,
    now: u64,
    release: Option<u64>,
    mirror: Option<u64>,
    cached: bool,
) -> Reason {
    let age = age_text(entry.age_secs(now));
    let text = match (code, release) {
        (ImageReason::PrebuiltFaster, Some(r)) => format!(
            "prebuilt image {} ({age}): release host {} MiB/s, apt mirror {}",
            entry.build_id,
            mibs_text(r),
            mirror.map_or("not measured".to_string(), |m| format!(
                "{} MiB/s",
                mibs_text(m)
            )),
        ),
        (ImageReason::ImageFile, _) => {
            format!(
                "prebuilt image {} ({age}) from the offline file",
                entry.build_id
            )
        }
        _ if cached => format!(
            "prebuilt image {} ({age}), already downloaded",
            entry.build_id
        ),
        _ => format!("prebuilt image {} ({age})", entry.build_id),
    };
    Reason::new(code, text)
}

/// Chooses the path of one `CreateDesktop`.
pub async fn choose<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    client: &Client<T>,
    req: &Request<'_>,
) -> Result<Decision, CmdError> {
    let mode = match req.mode {
        pb::ImageMode::Build => pb::ImageMode::Build,
        pb::ImageMode::Prebuilt => pb::ImageMode::Prebuilt,
        _ => pb::ImageMode::Auto,
    };
    // 1, 2.
    if let Some(name) = req.image_file {
        return offline(d, client, req, name).await;
    }
    if mode == pb::ImageMode::Build {
        return Ok(Decision::Build(Reason::new(
            ImageReason::BuildRequested,
            "build on the server was requested",
        )));
    }
    let auto = mode == pb::ImageMode::Auto;
    let deps = d.image_deps();
    let cfg = &d.cfg.image;
    // 3.
    if deps.keys.is_empty() {
        return fall(
            auto,
            ImageReason::NoImageKey,
            "building on the server: this agent has no image signing key, so no prebuilt image is accepted",
            refused("this agent has no image signing key, so no prebuilt image can be used")
                .at_stage(ProgressStage::Preflight),
        );
    }
    let digest = d
        .catalog
        .resolve(req.recipe, &[])
        .map_err(|e| CmdError::internal(sanitize_text(&e.to_string(), 200)))?
        .build_digest();
    let now = d.now();
    ctx.progress
        .stage(ProgressStage::Preflight, "looking for a prebuilt image");

    // 4 and 5: the list, then (after step 7) the speed probe, with one hold of the directory.
    let _dir = tokio::select! {
        g = d.image_dir_lock.lock() => g,
        reason = ctx.cancel.cancelled() => return Err(reason.error()),
    };
    let fetch = match Fetch::open(cfg, deps.clone(), ctx.cancel.clone(), ctx.progress.clone()) {
        Ok(f) => f,
        Err(ImgErr::Cancelled(e)) => return Err(e),
        Err(e) => {
            log::warn(&format!("image fetch: {}", e.text()));
            return fall(
                auto,
                ImageReason::ListUnavailable,
                "building on the server: the list of prebuilt images is not available",
                CmdError::unavailable("the list of prebuilt images is not available")
                    .at_stage(ProgressStage::ImageFetch),
            );
        }
    };
    let (bytes, sig) = match fetch.manifest().await {
        Ok(x) => x,
        Err(ImgErr::Cancelled(e)) => return Err(e),
        Err(ImgErr::Refused(m)) => {
            d.audit_notice(&format!(
                "image list not verified: {}",
                sanitize_text(&m, 120)
            ));
            return fall(
                auto,
                ImageReason::ListUnverified,
                "building on the server: the list of prebuilt images was refused",
                refused("the list of prebuilt images was refused")
                    .at_stage(ProgressStage::ImageFetch),
            );
        }
        Err(e) => {
            log::warn(&format!("image list: {}", e.text()));
            return fall(
                auto,
                ImageReason::ListUnavailable,
                "building on the server: the list of prebuilt images is not available",
                CmdError::unavailable("the list of prebuilt images is not available")
                    .at_stage(ProgressStage::ImageFetch),
            );
        }
    };
    let manifest = match verify_manifest(&deps.keys, &bytes, &sig, &d.cfg.update.arch, now) {
        Ok(m) => m,
        Err(why) => {
            d.audit_notice(&format!("image list not verified: {why}"));
            return fall(
                auto,
                ImageReason::ListUnverified,
                "building on the server: the list of prebuilt images did not verify",
                refused("the list of prebuilt images did not verify")
                    .at_stage(ProgressStage::ImageFetch),
            );
        }
    };
    // The replay counter, and its persistence only after the manifest is fully accepted.
    let fresh = d.read_images_state()?.is_fresh(manifest.timestamp);
    if !fresh {
        d.audit_notice("image list not verified: older than the newest list seen");
        return fall(
            auto,
            ImageReason::ListUnverified,
            "building on the server: the list of prebuilt images is older than one seen before",
            refused("the list of prebuilt images is older than one seen before")
                .at_stage(ProgressStage::ImageFetch),
        );
    }
    d.update_images_state(|s| s.accept(manifest.timestamp))?;

    // 6, 7.
    let Some(entry) = manifest.select(req.recipe, &digest, &d.cfg.update.running_version) else {
        return fall(
            auto,
            ImageReason::NoMatchingImage,
            "building on the server: no prebuilt image matches this recipe and this agent",
            refused("no prebuilt image matches this recipe and this agent"),
        );
    };
    if !entry.is_fresh(now) {
        let days = entry.age_secs(now) / 86_400;
        return fall(
            auto,
            ImageReason::ImageStale,
            &format!(
                "building on the server: the newest prebuilt image is {days} days old (limit {})",
                MAX_AGE_SECS / 86_400
            ),
            refused(format!(
                "the newest prebuilt image is {days} days old (limit {})",
                MAX_AGE_SECS / 86_400
            )),
        );
    }
    let entry = entry.clone();

    // 8, 9.
    let cached = cache::find_cached(d, client, &entry).await?;
    if let Err(short) = check_disk(
        d.probe.image_space(&cfg.state_dir, &cfg.incus_dir),
        req.pool,
        entry.size,
        entry.unpacked_size,
        cached,
    ) {
        let text = format!(
            "not enough disk for the prebuilt image (need {} GiB on {}, {} free)",
            gib_text(short.need),
            short.on,
            gib_text(short.free)
        );
        return fall(
            auto,
            ImageReason::Disk,
            &format!("building on the server: {text}"),
            CmdError::precondition(ErrorDetail::Pool, text),
        );
    }

    // 10.
    let (mut release_bps, mut mirror_bps) = (None, None);
    let code = if !auto {
        ImageReason::PrebuiltRequested
    } else if cached {
        ImageReason::PrebuiltFaster
    } else {
        let Some(recipe) = entry.recipe_id() else {
            return Err(CmdError::internal("a validated entry names no recipe"));
        };
        let job = ImageJob::Probe {
            recipe,
            build_id: entry.build_id.clone(),
        };
        let p = match fetch.probe(&job).await {
            Ok(p) => p,
            Err(ImgErr::Cancelled(e)) => return Err(e),
            Err(_) => ProbeResult::default(),
        };
        (release_bps, mirror_bps) = (p.release_bps, p.mirror_bps);
        match verdict(entry.size, &p) {
            Verdict::Prebuilt => ImageReason::PrebuiltFaster,
            Verdict::ProbeFailed => {
                return build(
                    ImageReason::ProbeFailed,
                    "building on the server: the speed of the release host could not be measured",
                );
            }
            Verdict::TooSlow(secs) => {
                let r = p.release_bps.unwrap_or(0);
                let est = if secs == u64::MAX {
                    "a very long time".to_string()
                } else {
                    format!("about {} min", secs.div_ceil(60))
                };
                return build(
                    ImageReason::DownloadTooSlow,
                    &format!(
                        "building on the server: downloading the prebuilt image would take {est} at {} MiB/s",
                        mibs_text(r)
                    ),
                );
            }
            Verdict::SlowerThanMirror => {
                return build(
                    ImageReason::SlowerThanMirror,
                    &format!(
                        "building on the server: the release host is slower than the apt mirror ({} vs {} MiB/s)",
                        mibs_text(p.release_bps.unwrap_or(0)),
                        mibs_text(p.mirror_bps.unwrap_or(0))
                    ),
                );
            }
        }
    };
    let reason = chosen_reason(code, &entry, now, release_bps, mirror_bps, cached);
    Ok(Decision::Prebuilt(
        Box::new(Selected {
            entry,
            source: Source::Online,
            cached,
            release_bps,
            mirror_bps,
            warnings: Vec::new(),
        }),
        reason,
    ))
}

/// The offline path: any failure is an error with no fallback (the administrator asked for this
/// file explicitly).
async fn offline<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    client: &Client<T>,
    req: &Request<'_>,
    name: &str,
) -> Result<Decision, CmdError> {
    let _ = client;
    let deps = d.image_deps();
    let cfg = &d.cfg.image;
    if deps.keys.is_empty() {
        return Err(refused(
            "this agent has no image signing key, so no offline image can be used",
        ));
    }
    let arch = &d.cfg.update.arch;
    let now = d.now();
    let dir = ImportDir::open(cfg, arch)?;
    let (bytes, sig) = dir.manifest()?;
    // No replay counter: an administrator may install an older, still signed image.
    let manifest = verify_manifest(&deps.keys, &bytes, &sig, arch, now).map_err(|why| {
        d.audit_notice(&format!("offline image manifest not verified: {why}"));
        refused("the offline manifest did not verify")
    })?;
    let digest = d
        .catalog
        .resolve(req.recipe, &[])
        .map_err(|e| CmdError::internal(sanitize_text(&e.to_string(), 200)))?
        .build_digest();
    let entry = manifest
        .select(req.recipe, &digest, &d.cfg.update.running_version)
        .ok_or_else(|| {
            refused(format!(
                "no entry of the offline manifest matches `{}` and this agent",
                recipe_name(req.recipe)
            ))
        })?
        .clone();
    let mut warnings = Vec::new();
    if !entry.is_fresh(now) {
        warnings.push(format!(
            "the offline image {} is {} days old",
            entry.build_id,
            entry.age_secs(now) / 86_400
        ));
    }
    if let Err(short) = check_disk(
        d.probe.image_space(&cfg.state_dir, &cfg.incus_dir),
        req.pool,
        entry.size,
        entry.unpacked_size,
        false,
    ) {
        return Err(CmdError::precondition(
            ErrorDetail::Pool,
            format!(
                "not enough disk for the offline image (need {} GiB on {}, {} free)",
                gib_text(short.need),
                short.on,
                gib_text(short.free)
            ),
        ));
    }
    let reason = chosen_reason(ImageReason::ImageFile, &entry, now, None, None, false);
    Ok(Decision::Prebuilt(
        Box::new(Selected {
            entry,
            source: Source::Offline {
                dir,
                name: name.to_string(),
            },
            cached: false,
            release_bps: None,
            mirror_bps: None,
            warnings,
        }),
        reason,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn space(state: u64, incus: u64, same: bool) -> Option<ImageSpace> {
        Some(ImageSpace {
            state_free: state,
            incus_free: incus,
            same_device: same,
        })
    }

    const POOL_OK: (u64, u64) = (100 * GIB, 80 * GIB);

    #[test]
    fn the_disk_rule_has_one_device_and_two_device_forms() {
        let (s, u) = (GIB, 3 * GIB);
        // Two devices: S + 1 GiB on each.
        assert!(check_disk(space(2 * GIB, 2 * GIB, false), POOL_OK, s, u, false).is_ok());
        let e = check_disk(space(2 * GIB - 1, 9 * GIB, false), POOL_OK, s, u, false).unwrap_err();
        assert_eq!((e.need, e.on), (2 * GIB, "/var/lib/hx"));
        let e = check_disk(space(9 * GIB, 2 * GIB - 1, false), POOL_OK, s, u, false).unwrap_err();
        assert_eq!(e.on, "/var/lib/incus");
        // One device: 2S + 2 GiB.
        assert!(check_disk(space(4 * GIB, 4 * GIB, true), POOL_OK, s, u, false).is_ok());
        let e =
            check_disk(space(4 * GIB - 1, 4 * GIB - 1, true), POOL_OK, s, u, false).unwrap_err();
        assert_eq!((e.need, e.on), (4 * GIB, "/var/lib"));
        // Unreadable space fails closed.
        assert!(check_disk(None, POOL_OK, s, u, false).is_err());
    }

    #[test]
    fn the_pool_needs_the_unpacked_size_plus_eight_gib_and_fifteen_percent() {
        let sp = space(100 * GIB, 100 * GIB, false);
        let (s, u) = (GIB, 10 * GIB);
        assert!(check_disk(sp, (100 * GIB, 18 * GIB), s, u, false).is_ok());
        let e = check_disk(sp, (100 * GIB, 18 * GIB - 1), s, u, false).unwrap_err();
        assert_eq!(e.on, "the storage pool");
        // Plenty for the image but under 15% of a big pool.
        assert!(check_disk(sp, (1000 * GIB, 100 * GIB), s, u, false).is_err());
        // A cached image skips the copy checks and still needs the pool.
        assert!(check_disk(None, POOL_OK, s, u, true).is_ok());
        assert!(check_disk(None, (100 * GIB, 5 * GIB), s, u, true).is_err());
    }

    fn probe(rel: Option<u64>, mir: Option<u64>) -> ProbeResult {
        ProbeResult {
            release_bps: rel,
            mirror_bps: mir,
        }
    }

    #[test]
    fn the_speed_verdict_follows_the_three_rules() {
        let mb = 1024 * 1024;
        let s = 900 * mb;
        // Failed release probe.
        assert_eq!(
            verdict(s, &probe(None, Some(10 * mb))),
            Verdict::ProbeFailed
        );
        // S / r above 900 s: exactly 900 s is allowed.
        assert_eq!(verdict(s, &probe(Some(mb), None)), Verdict::Prebuilt);
        assert!(matches!(
            verdict(s + 1, &probe(Some(mb), None)),
            Verdict::TooSlow(900)
        ));
        assert!(matches!(
            verdict(s, &probe(Some(0), None)),
            Verdict::TooSlow(_)
        ));
        // Half the mirror is allowed, less is not.
        assert_eq!(
            verdict(mb, &probe(Some(10 * mb), Some(20 * mb))),
            Verdict::Prebuilt
        );
        assert_eq!(
            verdict(mb, &probe(Some(10 * mb - 1), Some(20 * mb))),
            Verdict::SlowerThanMirror
        );
        // A failed mirror probe alone allows the prebuilt image.
        assert_eq!(verdict(mb, &probe(Some(10 * mb), None)), Verdict::Prebuilt);
    }

    #[test]
    fn numbers_in_reasons_are_plain_text() {
        assert_eq!(gib_text(GIB * 41 / 10), "4.0");
        assert_eq!(gib_text(4 * GIB + GIB / 10 * 2), "4.1");
        assert_eq!(gib_text(0), "0.0");
        assert_eq!(mibs_text(40_000_000), "38.1");
        assert_eq!(mibs_text(1024 * 1024), "1.0");
        assert_eq!(age_text(10), "less than a day old");
        assert_eq!(age_text(86_400 * 2), "2 days old");
        assert!(Reason::new(ImageReason::Disk, "x".repeat(1000)).text.len() <= 256);
    }
}
