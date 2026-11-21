//! `CheckUpdate`, `ApplyUpdate`, `RollbackUpdate` (ipc.md 6.12). The pieces are in
//! `privd::update`; the part that runs in the **next** process after the re-exec is in
//! `update_resume`.
//!
//! * `CheckUpdate` (A): fetch the signed manifest through the sandboxed fetcher, verify it, record
//!   its timestamp, stage the verified copy, report what is available.
//! * `ApplyUpdate` (A): only the version `CheckUpdate` verified, strictly newer, for this
//!   architecture. Fetch the artifact, check size and SHA-256 against the signed manifest, take a
//!   `preupdate` snapshot, unpack safely, switch `current`, answer `restarting`, then restart
//!   gatewayd and re-exec privd. The health check and the automatic rollback follow in the new
//!   process.
//! * `RollbackUpdate` (X): flip `current` and `previous`, restart both.
//!
//! All three take the host lock, so a check, an apply and a rollback never overlap, and the
//! fetch directory has one user at a time.

use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use hx_ipc::privd::pb::{self, ErrorDetail, ProgressStage, Role, response};
use hx_ipc::privd::snapshot_kind_of;
use hx_ipc::text::sanitize_text;
use hx_provision::incus::Transport;

use crate::fetcher::{ARTIFACT_FILE, Job, MANIFEST_FILE, MANIFEST_SIG_FILE, MAX_MANIFEST_BYTES};
use crate::privd::daemon::{Ctx, Daemon, Reply};
use crate::privd::error::CmdError;
use crate::privd::log;
use crate::privd::state::write_atomic;
use crate::privd::timefmt::snapshot_stamp;
use crate::privd::update::extract::{self, ExtractError, Limits};
use crate::privd::update::fetchdir::{self, FetchDir, ReadError};
use crate::privd::update::manifest::{Expect, Manifest, ManifestError, Release};
use crate::privd::update::state::{Pending, UpdateState};
use crate::privd::update::switch::Layout;
use crate::privd::update::verify::digest_eq;
use crate::privd::update::version::Version;
use crate::privd::update::{UpdateDeps, UpdateKeys};

use super::update_resume::schedule_restarts;

/// Largest signature file.
const MAX_SIG_BYTES: u64 = 16 * 1024;
/// The `preupdate` snapshots kept per desktop (the new one included).
const KEEP_PREUPDATE: usize = 2;
/// While a rolled-back release is on record, rotation is suspended up to this many snapshots, so
/// that the one taken before the first bad update survives a re-apply loop.
const PRESERVE_PREUPDATE: usize = 4;
/// A manifest older than this is reported as a possible freeze.
const MAX_MANIFEST_AGE_DAYS: u64 = 90;
const DAY: u64 = 86_400;
/// `ApplyUpdate` admissions per day (ipc.md 8); persisted in `updates-state`.
const APPLY_PER_DAY: usize = 2;

fn refused(msg: impl Into<String>) -> CmdError {
    CmdError::precondition(ErrorDetail::Unspecified, msg)
}

/// What the fetcher left was not acceptable (or not there).
fn read_error(e: ReadError) -> CmdError {
    match e {
        ReadError::Missing(n) => {
            CmdError::unavailable(format!("the update fetcher produced no `{n}`"))
        }
        other => refused(format!("the fetcher's output was refused: {other}")),
    }
}

fn load_state<T: Transport + Clone + 'static>(d: &Daemon<T>) -> Result<UpdateState, CmdError> {
    UpdateState::load(&d.store).map_err(|e| {
        log::error(&format!("updates-state: {e}"));
        CmdError::internal("privd's update state cannot be read")
    })
}

fn save_state<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    st: &UpdateState,
) -> Result<(), CmdError> {
    st.save(&d.store).map_err(|e| {
        log::error(&format!("updates-state: {e}"));
        CmdError::internal("privd's update state cannot be saved")
    })
}

fn layout<T: Transport + Clone + 'static>(d: &Daemon<T>) -> Layout {
    Layout::new(&d.cfg.update.versions_dir)
}

fn running_version<T: Transport + Clone + 'static>(d: &Daemon<T>) -> Result<Version, CmdError> {
    Version::parse(&d.cfg.update.running_version)
        .ok_or_else(|| CmdError::internal("the running version is not a release version"))
}

fn ensure_dirs<T: Transport + Clone + 'static>(d: &Daemon<T>) -> Result<FetchDir, CmdError> {
    let u = &d.cfg.update;
    // 1733: the fetcher's dynamic user reaches it only through the unit's bind mount (the state
    // directory above is 0700), may create files in it but not list or remove others'.
    fetchdir::ensure_dir(&u.fetch_dir, 0o1733)
        .and_then(|()| fetchdir::ensure_dir(&u.staging_dir, 0o700))
        .map_err(|e| {
            log::error(&format!("update directories: {e}"));
            CmdError::internal("privd's update directories are not usable")
        })?;
    let dir = FetchDir::open(&u.fetch_dir).map_err(|e| {
        log::error(&format!("fetch directory: {e}"));
        CmdError::internal("the fetch directory cannot be opened")
    })?;
    dir.sweep(&[MANIFEST_FILE, MANIFEST_SIG_FILE, ARTIFACT_FILE])
        .map_err(|e| {
            log::error(&format!("fetch directory: {e}"));
            CmdError::internal("the fetch directory cannot be cleared")
        })?;
    Ok(dir)
}

async fn run_fetcher(ctx: &Ctx, deps: &UpdateDeps, job: Job) -> Result<(), CmdError> {
    tokio::select! {
        r = deps.systemd.fetch(&job) => r.map_err(CmdError::unavailable),
        reason = ctx.cancel.cancelled() => Err(reason.error()),
    }
}

/// Reads a file privd itself staged (root-only directory): no symlink, a regular file, bounded.
fn read_staged(path: &Path, max: u64) -> Result<Vec<u8>, CmdError> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| refused("no verified release is staged; run CheckUpdate first"))?;
    let m = f.metadata()?;
    if !m.is_file() || m.len() > max || m.uid() != rustix::process::geteuid().as_raw() {
        return Err(refused(
            "the staged release is not acceptable; run CheckUpdate again",
        ));
    }
    let mut buf = Vec::new();
    f.take(max).read_to_end(&mut buf)?;
    Ok(buf)
}

/// Verifies signature and fields of manifest bytes; the one place both commands do it.
fn verify_manifest<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    keys: &UpdateKeys,
    bytes: &[u8],
    sig: &[u8],
) -> Result<Release, CmdError> {
    let sig = std::str::from_utf8(sig).map_err(|_| refused("the signature file is not text"))?;
    keys.verify(bytes, sig)
        .map_err(|e| refused(format!("the release manifest was refused: {e}")))?;
    let u = &d.cfg.update;
    Manifest::parse(bytes)
        .and_then(|m| {
            m.check(&Expect {
                channel: u.channel.as_str(),
                arch: &u.arch,
                now: d.now(),
            })
        })
        .map_err(|e: ManifestError| refused(format!("the release manifest was refused: {e}")))
}

fn refusal_notice<T: Transport + Clone + 'static>(d: &Daemon<T>, what: &str, e: &CmdError) {
    d.audit_notice(&format!(
        "update {what} refused: {}",
        sanitize_text(&e.message, 160)
    ));
}

/// `CheckUpdate` (class A, both roles). The channel comes from `privd.toml`, not the request.
pub async fn check<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
) -> Result<Reply, CmdError> {
    let r = check_inner(d, ctx).await;
    if let Err(e) = &r {
        refusal_notice(d, "check", e);
    }
    r
}

async fn check_inner<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
) -> Result<Reply, CmdError> {
    let deps = d.update_deps();
    let u = &d.cfg.update;
    let _g = d.lock_host(ctx).await?;
    let mut st = load_state(d)?;
    if st.pending.is_some() {
        return Err(refused(
            "an update is being applied; its health check has not finished",
        ));
    }
    if deps.keys.is_empty() {
        return Err(refused(
            "this build embeds no release signing key, so updates are disabled",
        ));
    }
    let running = running_version(d)?;
    ctx.progress
        .stage(ProgressStage::Update, "checking for updates");

    let dir = ensure_dirs(d)?;
    run_fetcher(ctx, &deps, Job::Manifest(u.channel)).await?;
    // Read once, verify what is used (rule 2).
    let manifest = dir
        .read_small(MANIFEST_FILE, MAX_MANIFEST_BYTES)
        .map_err(read_error)?;
    let sig = dir
        .read_small(MANIFEST_SIG_FILE, MAX_SIG_BYTES)
        .map_err(read_error)?;
    drop(dir);
    let release = verify_manifest(d, &deps.keys, &manifest, &sig)?;

    // Rule 3: freshness. A replayed older (signed, possibly vulnerable) manifest is refused.
    if !st.is_fresh(u.channel.as_str(), release.manifest.timestamp) {
        return Err(refused(
            "the release manifest is older than one already accepted (replay)",
        ));
    }
    st.accept(u.channel.as_str(), release.manifest.timestamp);
    // A manifest that is fresh by the counter but old by the calendar may be a freeze (an
    // attacker replaying the newest manifest they hold). Not a hard failure: a project that
    // simply stopped releasing must not lose its updates path; the audit log and the journal say
    // so (there is no needs_attention flag for it in the wire enum).
    let age_days = d.now().saturating_sub(release.manifest.timestamp) / 86_400;
    if age_days > MAX_MANIFEST_AGE_DAYS {
        log::warn(&format!("update: the release manifest is {age_days} days old"));
        d.audit_notice(&format!(
            "update check: the release manifest is {age_days} days old (possible freeze)"
        ));
    }

    let staged_manifest = u.staging_dir.join(MANIFEST_FILE);
    let staged_sig = u.staging_dir.join(MANIFEST_SIG_FILE);
    let available = if release.version > running {
        write_atomic(&staged_manifest, &manifest, 0o600)?;
        write_atomic(&staged_sig, &sig, 0o600)?;
        st.verified_version = Some(release.manifest.version.clone());
        Some(release.manifest.version.clone())
    } else {
        let _ = std::fs::remove_file(&staged_manifest);
        let _ = std::fs::remove_file(&staged_sig);
        st.verified_version = None;
        None
    };
    save_state(d, &st)?;
    d.audit_notice(&format!(
        "update check: running {}, available {}",
        u.running_version,
        available.as_deref().unwrap_or("none")
    ));
    Ok(response::Result::CheckUpdate(pb::CheckUpdateResult {
        current: u.running_version.clone(),
        available,
        channel: channel_pb(u.channel) as i32,
        verified: true,
        rolled_back: st.rolled_back.map(|r| pb::RolledBack {
            version: r.version,
            reason: r.reason,
        }),
    }))
}

fn channel_pb(c: crate::fetcher::Channel) -> pb::UpdateChannel {
    match c {
        crate::fetcher::Channel::Stable => pb::UpdateChannel::Stable,
        crate::fetcher::Channel::Beta => pb::UpdateChannel::Beta,
    }
}

/// `ApplyUpdate` (class A, both roles).
pub async fn apply<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::ApplyUpdateRequest,
) -> Result<Reply, CmdError> {
    let res = apply_inner(d, ctx, &r.version).await;
    if let Err(e) = &res {
        refusal_notice(d, "apply", e);
    }
    res
}

async fn apply_inner<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    version: &str,
) -> Result<Reply, CmdError> {
    let deps = d.update_deps();
    let u = &d.cfg.update;
    let _g = d.lock_host(ctx).await?;
    let mut st = load_state(d)?;
    let now = d.now();
    // A release that failed its health check, or that an Admin rolled back, is not re-applied
    // by Gateway for 24 h: a loop of apply and rollback would restart units and rotate away the
    // recovery snapshot.
    let recently = |r: &Option<crate::privd::update::state::RolledBack>| {
        r.as_ref()
            .is_some_and(|r| r.version == version && now.saturating_sub(r.at) < DAY)
    };
    if ctx.role != Role::Admin && (recently(&st.rolled_back) || recently(&st.manual_rollback)) {
        return Err(CmdError::denied(
            "that release was rolled back; only an Admin may re-apply it within 24 hours",
        ));
    }
    // The 2-a-day limit, kept in updates-state so a restart (or the rollback itself) does not
    // reset it.
    st.apply_log.retain(|t| now.saturating_sub(*t) < DAY);
    if st.apply_log.len() >= APPLY_PER_DAY {
        let oldest = st.apply_log.iter().min().copied().unwrap_or(now);
        let retry = (oldest + DAY).saturating_sub(now).saturating_mul(1000);
        return Err(CmdError::exhausted(
            "ApplyUpdate is limited to 2 a day",
            u32::try_from(retry).unwrap_or(u32::MAX),
        ));
    }
    st.apply_log.push(now);
    save_state(d, &st)?;
    if st.pending.is_some() {
        return Err(refused(
            "an update is already being applied; its health check has not finished",
        ));
    }
    if deps.keys.is_empty() {
        return Err(refused(
            "this build embeds no release signing key, so updates are disabled",
        ));
    }
    let want = Version::parse(version).ok_or_else(|| CmdError::invalid("apply_update.version"))?;
    let running = running_version(d)?;
    // Rule 10: forward only. No downgrade, no re-install of the running version, by request.
    if want <= running {
        return Err(refused(
            "the version is not newer than the running one; downgrades are refused",
        ));
    }

    // The release must be one privd has itself fetched and verified: re-verify the staged copy
    // against the embedded keys (cheap) rather than trusting a flag.
    let manifest = read_staged(&u.staging_dir.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
    let sig = read_staged(&u.staging_dir.join(MANIFEST_SIG_FILE), MAX_SIG_BYTES)?;
    let release = verify_manifest(d, &deps.keys, &manifest, &sig)?;
    if release.version != want {
        return Err(refused(
            "that version is not the verified release; run CheckUpdate first",
        ));
    }
    // From here on the canonical string of the signed manifest is used, never the caller's
    // (`01.1.0` and `1.1.0` compare equal but are different path names).
    if release.manifest.version != version {
        return Err(CmdError::invalid(
            "apply_update.version: not the canonical form of the verified version",
        ));
    }
    let version: &str = &release.manifest.version;
    if !st.is_fresh(u.channel.as_str(), release.manifest.timestamp) {
        return Err(refused(
            "the verified release is older than one already accepted; run CheckUpdate again",
        ));
    }
    if let Some(min) = release.min_previous
        && running < min
    {
        return Err(refused(format!(
            "the running version is too old to update straight to {version} (needs at least {min})"
        )));
    }
    ctx.check_cancelled()?;

    // Fetch the artifact and keep one verified copy.
    ctx.progress.emit(
        ProgressStage::Update,
        1,
        5,
        "downloading the release",
        255,
        true,
    );
    let dir = ensure_dirs(d)?;
    run_fetcher(ctx, &deps, Job::Artifact(version.to_string())).await?;
    let staging = u.staging_dir.clone();
    let size = release.manifest.size;
    // Copying up to 256 MiB is blocking work; the directory descriptor moves into the task and
    // is closed with it (the fetcher's file is never reopened).
    let staged =
        tokio::task::spawn_blocking(move || dir.stage_large(ARTIFACT_FILE, size, &staging))
            .await
            .map_err(|_| CmdError::internal("the copy task failed"))?
            .map_err(read_error)?;
    if !digest_eq(&staged.sha256, &release.manifest.sha256) {
        return Err(refused(
            "the artifact's SHA-256 does not match the signed manifest",
        ));
    }
    ctx.check_cancelled()?;

    // A snapshot first, so that a bad update that corrupts the desktop can be undone.
    ctx.progress.emit(
        ProgressStage::Update,
        2,
        5,
        "snapshotting the desktop",
        255,
        true,
    );
    preupdate_snapshots(d, ctx, st.rolled_back.is_some() || st.manual_rollback.is_some()).await;
    ctx.check_cancelled()?;

    // Rule 4: safe extraction from the verified copy.
    ctx.progress.emit(
        ProgressStage::Update,
        3,
        5,
        "unpacking the release",
        255,
        true,
    );
    let lay = layout(d);
    let (incoming, fd) = lay.begin(version).map_err(|e| {
        log::error(&format!("release directory: {e}"));
        CmdError::internal("the release directory is not usable")
    })?;
    let cancel = ctx.cancel.clone();
    let file = staged.file;
    let extracted = tokio::task::spawn_blocking(move || {
        extract::extract_tar_gz(file, fd.as_fd(), &Limits::default(), &|| {
            cancel.reason().is_some()
        })
    })
    .await
    .map_err(|_| CmdError::internal("the unpack task failed"))?;
    if let Err(e) = extracted {
        lay.discard(&incoming);
        return Err(match e {
            ExtractError::Cancelled => ctx
                .cancel
                .reason()
                .map_or_else(CmdError::cancelled, |r| r.error()),
            ExtractError::Io(e) => {
                log::error(&format!("extraction: {e}"));
                CmdError::internal("the release could not be unpacked")
            }
            other => refused(format!("the verified artifact was refused: {other}")),
        });
    }
    let published = lay
        .verify_incoming(&incoming, version)
        .map_err(refused)
        .and_then(|()| {
            lay.publish(&incoming, version).map_err(|e| {
                log::error(&format!("publishing {version}: {e}"));
                refused("the release directory could not be published")
            })
        });
    if let Err(e) = published {
        lay.discard(&incoming);
        return Err(e);
    }

    // The point of no return: after the switch the update proceeds whatever the caller does.
    ctx.check_cancelled()?;
    ctx.progress
        .emit(ProgressStage::Update, 4, 5, "switching versions", 255, true);
    let previous = lay.current().ok().flatten();
    st.pending = Some(Pending {
        version: version.to_string(),
        previous,
        started_unix: d.now(),
        attempts: 0,
        gateway_pid: deps
            .systemd
            .state(crate::privd::update::Unit::Gatewayd)
            .await
            .ok()
            .map(|s| s.main_pid)
            .filter(|p| *p != 0),
    });
    st.verified_version = None;
    save_state(d, &st)?;
    if let Err(e) = lay.switch_to(version) {
        log::error(&format!("switch to {version}: {e}"));
        st.pending = None;
        let _ = st.save(&d.store);
        return Err(CmdError::internal("the version could not be switched"));
    }
    d.audit_notice(&format!(
        "update {version} switched in (running {})",
        u.running_version
    ));
    ctx.progress
        .emit(ProgressStage::Update, 5, 5, "restarting", 255, true);
    schedule_restarts(d, true);
    Ok(response::Result::ApplyUpdate(pb::ApplyUpdateResult {
        restarting: true,
    }))
}

/// `RollbackUpdate` (class X, Admin only): back to the previous retained version.
pub async fn rollback<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
) -> Result<Reply, CmdError> {
    // Class X is enforced at admission; this is the second line.
    if ctx.role != Role::Admin {
        return Err(CmdError::denied("rollback_update: Admin only"));
    }
    let _g = d.lock_host(ctx).await?;
    let mut st = load_state(d)?;
    if st.pending.is_some() {
        return Err(refused(
            "an update is being applied; its health check decides whether it rolls back",
        ));
    }
    // The release that was rolled back for failing its health check is not an acceptable
    // target: `previous` points at it after an automatic rollback.
    if let (Some(rb), Ok(Some(prev))) = (&st.rolled_back, layout(d).previous())
        && rb.version == prev
    {
        return Err(refused(
            "the previous version is the release that failed its health check; it is not a rollback target",
        ));
    }
    let (from, to) = layout(d).swap_back().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            refused("there is no previous version to roll back to")
        } else {
            log::error(&format!("rollback: {e}"));
            refused("the previous version is not intact; it cannot be switched to")
        }
    })?;
    st.manual_rollback = Some(crate::privd::update::state::RolledBack {
        version: from.clone(),
        reason: "rolled back by an administrator".into(),
        at: d.now(),
    });
    save_state(d, &st)?;
    d.audit_notice(&format!("update rollback: {from} -> {to}"));
    schedule_restarts(d, false);
    Ok(response::Result::RollbackUpdate(
        pb::RollbackUpdateResult {},
    ))
}

/// `hx-preupdate-<utc>-<4 hex>`, matching ipc.md 6.10.
fn preupdate_name(now: u64) -> Result<String, CmdError> {
    let mut b = [0u8; 2];
    getrandom::fill(&mut b).map_err(|_| CmdError::internal("no randomness"))?;
    Ok(format!(
        "hx-preupdate-{}-{:02x}{:02x}",
        snapshot_stamp(now),
        b[0],
        b[1]
    ))
}

/// Best effort: a `preupdate` snapshot of every ready desktop, keeping the newest two. Any
/// failure is logged and the update goes on (ipc.md 6.12: "best effort").
async fn preupdate_snapshots<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &Ctx,
    preserve: bool,
) {
    let ids: Vec<String> = d.read_state(|s| s.desktops.keys().cloned().collect());
    for id in ids {
        let Ok(_g) = d.lock_desktop(ctx, &id, false).await else {
            log::warn("update: a desktop is busy; no preupdate snapshot of it");
            continue;
        };
        let Ok(l) = d.load_desktop(&id).await else {
            continue;
        };
        if l.meta.state != "ready" {
            continue;
        }
        let client = d.incus.scoped();
        let result: Result<(), CmdError> = async {
            let mut old: Vec<String> = client
                .list_snapshots(&l.name)
                .await?
                .into_iter()
                .filter(|s| snapshot_kind_of(&s.name) == Some("preupdate"))
                .map(|s| s.name)
                .collect();
            old.sort();
            if preserve {
                // A rolled-back release is on record: keep what exists (the snapshot before the
                // first bad update included) and stop adding at the cap.
                if old.len() >= PRESERVE_PREUPDATE {
                    return Ok(());
                }
            } else {
                while old.len() >= KEEP_PREUPDATE {
                    client.delete_snapshot(&l.name, &old.remove(0)).await?;
                }
            }
            client
                .create_snapshot(&l.name, &preupdate_name(d.now())?)
                .await?;
            Ok(())
        }
        .await;
        if let Err(e) = result {
            log::warn(&format!(
                "update: preupdate snapshot of `{id}` failed: {}",
                e.message
            ));
        }
    }
}
