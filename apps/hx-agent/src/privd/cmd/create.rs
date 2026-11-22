//! `CreateDesktop` (ipc.md 6.5): from the recipe through `ready`, converging and cleaning up.
//!
//! What a caller chooses: the recipe (distro, desktop, preset), the username, the image mode, the
//! limits (within the host bounds), whether to enable Docker (with the acknowledgement), the
//! validated settings, and the password (secret slot 0). Everything else is derived here: the
//! instance name, the recipe catalog (`Catalog::embedded`, never a directory), the base image,
//! the profiles. The password reaches `hx_provision::run_post_stage` only through
//! `Secrets::with_user_password`.
//!
//! Failure and cancel: privd destroys the instance it created in this request (a forced stop,
//! which is what ends exec operations that cannot be cancelled on Incus 6.0.0, then a delete),
//! waits for every Incus operation of the request to end, and only then answers. The error names
//! the failing stage.

use std::time::Instant;

use hx_ipc::privd::pb::{self, ErrorDetail, ImageReason, ProgressStage, Role, response};
use hx_ipc::text::sanitize_text;
use hx_provision::exec::{Secrets, StageReport};
use hx_provision::incus::{ImageSource, Transport};
use hx_provision::orchestrate::{
    DesktopSpec, Limits, ProvisionError, build_on_server, finish_prebuilt,
};
use hx_provision::{Settings, Username};

use super::common::{HostBounds, host_bounds, recipe_from_pb, recipe_text, validate_limits};
use super::docker::enable_flow;
use super::session::{install_inner, provision_link_inner};
use crate::privd::daemon::{Ctx, Daemon, Reply};
use crate::privd::error::CmdError;
use crate::privd::image::cache;
use crate::privd::image::choose::{
    Decision, Reason, Request as ChooseRequest, Selected, Source, choose,
};
use crate::privd::image::fetch::Fetch;

const GIB: u64 = 1 << 30;
/// Free pool space needed to start: at least 8 GiB and 15% (ipc.md 6.5 step 1).
const MIN_FREE_GIB: u64 = 8;

/// The stage a `ProvisionError` happened in, for the error's `stage` field.
pub fn stage_of(e: &ProvisionError) -> ProgressStage {
    use hx_provision::Stage;
    match e {
        ProvisionError::Apply(hx_provision::ApplyError::Step { stage, .. })
        | ProvisionError::Apply(hx_provision::ApplyError::MissingSecret { stage, .. }) => {
            match stage {
                Stage::Build => ProgressStage::Build,
                Stage::Post => ProgressStage::Post,
            }
        }
        _ => ProgressStage::Launch,
    }
}

fn provision_err(e: ProvisionError) -> CmdError {
    let stage = stage_of(&e);
    CmdError::from(e).at_stage(stage)
}

/// The validated `Settings` of a request; an empty message does nothing.
pub fn build_settings(
    s: &pb::DesktopSettings,
    zoneinfo: &std::path::Path,
) -> Result<Settings, CmdError> {
    let bad =
        |e: hx_provision::SettingsError| CmdError::invalid(format!("create_desktop.settings: {e}"));
    let mut out = Settings::none();
    if !s.hostname.is_empty() {
        out = out.with_hostname(&s.hostname).map_err(bad)?;
    }
    if !s.timezone.is_empty() {
        out = out.with_timezone_in(&s.timezone, zoneinfo).map_err(bad)?;
    }
    if !s.locale.is_empty() {
        out = out.with_locale(&s.locale).map_err(bad)?;
    }
    if !s.keyboard.is_empty() {
        out = out.with_keyboard(&s.keyboard).map_err(bad)?;
    }
    Ok(out)
}

/// Resolves the limits of a request: omitted fields get privd's defaults (all host CPUs; host RAM
/// minus the reserve; 80% of the pool), then every bound of ipc.md 6.8 is checked.
pub fn resolve_limits(
    l: Option<&pb::Limits>,
    b: &HostBounds,
    pool_total_gib: u64,
) -> Result<(u32, u64, u64), CmdError> {
    let l = l.cloned().unwrap_or_default();
    let cpu = if l.cpu == 0 { b.cpus } else { l.cpu };
    let mem = if l.memory_mib == 0 {
        b.max_memory_mib()
    } else {
        l.memory_mib
    };
    let disk = if l.disk_gib == 0 {
        (pool_total_gib * 8 / 10).min(b.pool_free_gib)
    } else {
        l.disk_gib
    };
    validate_limits(cpu, mem, disk, b, 1)?;
    Ok((cpu, mem, disk))
}

fn sum_ms(r: &Option<StageReport>) -> u32 {
    r.as_ref()
        .map(|r| r.timings.iter().map(|(_, d)| d.as_millis()).sum::<u128>())
        .map_or(0, |ms| u32::try_from(ms).unwrap_or(u32::MAX))
}

fn warnings_of(r: &hx_provision::orchestrate::ProvisionReport) -> Vec<String> {
    let mut v = Vec::new();
    for rep in [&r.build, &r.post].into_iter().flatten() {
        for w in &rep.warnings {
            v.push(sanitize_text(&format!("{}: {}", w.step, w.message), 256));
        }
    }
    v
}

/// What the image path of one request produced (the build or the prebuilt path, whichever ran).
struct Provisioned {
    report: hx_provision::orchestrate::ProvisionReport,
    path: pb::PathTaken,
    reason: Reason,
    image: Option<pb::ImageInfo>,
    /// Timings of the stages before the build/post stages (`IMAGE_FETCH`, `IMAGE_IMPORT`).
    image_timings: Vec<pb::StageTiming>,
    warnings: Vec<String>,
    /// The imported image to delete once the desktop is `ready`.
    delete_after_ready: Option<String>,
}

/// A prebuilt attempt that failed: where, why, and whether the post stage (which handles the
/// password, and which a build would run again) had begun.
struct Fail {
    stage: ProgressStage,
    err: CmdError,
    before_post: bool,
}

impl Fail {
    fn new(stage: ProgressStage, err: CmdError) -> Self {
        let err = if err.stage.is_some() {
            err
        } else {
            err.at_stage(stage)
        };
        Self {
            stage,
            err,
            before_post: true,
        }
    }
}

fn ms_since(t: Instant) -> u32 {
    u32::try_from(t.elapsed().as_millis()).unwrap_or(u32::MAX)
}

/// The fixed name of a stage in a reason string.
fn stage_name(s: ProgressStage) -> &'static str {
    match s {
        ProgressStage::ImageFetch => "IMAGE_FETCH",
        ProgressStage::ImageImport => "IMAGE_IMPORT",
        ProgressStage::Launch => "LAUNCH",
        ProgressStage::Post => "POST",
        _ => "PREFLIGHT",
    }
}

/// Everything the two paths share.
struct Env<'a, T: Transport + Clone + 'static> {
    d: &'a Daemon<T>,
    ctx: &'a Ctx,
    client: &'a hx_provision::incus::Client<T>,
    plan: &'a hx_provision::Plan,
    spec: &'a DesktopSpec,
    secrets: &'a Secrets,
    /// Set once the post stage (the one that handles the password) has begun.
    in_post: &'a std::sync::atomic::AtomicBool,
    name: &'a str,
}

impl<T: Transport + Clone + 'static> Env<'_, T> {
    fn callback<'b>(&'b self) -> Box<dyn FnMut(&hx_provision::Progress) + Send + 'b> {
        let progress = self.ctx.progress.clone();
        let in_post = self.in_post;
        Box::new(move |p: &hx_provision::Progress| {
            // From the first post-stage step on, the password is in play.
            if let hx_provision::Progress::Started {
                stage: hx_provision::Stage::Post,
                ..
            } = p
            {
                in_post.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            progress.from_provision(p);
        })
    }

    /// The build path: from the recipe's base image.
    async fn build(&self, reason: Reason) -> Result<Provisioned, CmdError> {
        let mut cb = self.callback();
        self.ctx
            .progress
            .stage(ProgressStage::Build, "building the desktop");
        let report = build_on_server(self.client, self.plan, self.spec, self.secrets, &mut cb)
            .await
            .map_err(provision_err)?;
        Ok(Provisioned {
            report,
            path: pb::PathTaken::Build,
            reason,
            image: None,
            image_timings: Vec::new(),
            warnings: Vec::new(),
            delete_after_ready: None,
        })
    }

    /// The prebuilt path: fetch (or read the offline file), import, launch, post, restart.
    async fn prebuilt(&self, sel: &mut Selected, reason: &Reason) -> Result<Provisioned, Fail> {
        let (d, ctx, client) = (self.d, self.ctx, self.client);
        let cfg = &d.cfg.image;
        let entry = sel.entry.clone();
        let mut image_timings = Vec::new();
        let mut warnings = std::mem::take(&mut sel.warnings);

        let staged = if sel.cached {
            None
        } else {
            let t = Instant::now();
            ctx.progress
                .stage(ProgressStage::ImageFetch, "fetching the desktop image");
            let staged = match &sel.source {
                Source::Online => {
                    let _dir = tokio::select! {
                        g = d.image_dir_lock.lock() => g,
                        reason = ctx.cancel.cancelled() => {
                            return Err(Fail::new(ProgressStage::ImageFetch, reason.error()));
                        }
                    };
                    let fetch = Fetch::open(
                        cfg,
                        d.image_deps(),
                        ctx.cancel.clone(),
                        ctx.progress.clone(),
                    )
                    .map_err(|e| {
                        Fail::new(
                            ProgressStage::ImageFetch,
                            e.into_cmd(ProgressStage::ImageFetch),
                        )
                    })?;
                    fetch.image(&entry).await.map_err(|e| {
                        Fail::new(
                            ProgressStage::ImageFetch,
                            e.into_cmd(ProgressStage::ImageFetch),
                        )
                    })?
                }
                Source::Offline { dir, name } => dir
                    .stage(name, &entry, cfg)
                    .await
                    .map_err(|e| Fail::new(ProgressStage::ImageFetch, e))?,
            };
            image_timings.push(pb::StageTiming {
                stage: ProgressStage::ImageFetch as i32,
                elapsed_ms: ms_since(t),
            });
            Some(staged)
        };
        ctx.check_cancelled()
            .map_err(|e| Fail::new(ProgressStage::ImageFetch, e))?;

        if let Some(staged) = staged {
            let t = Instant::now();
            ctx.progress
                .stage(ProgressStage::ImageImport, "importing the desktop image");
            cache::import(d, client, &entry, staged, cfg.import_wait)
                .await
                .map_err(|e| Fail::new(ProgressStage::ImageImport, e))?;
            image_timings.push(pb::StageTiming {
                stage: ProgressStage::ImageImport as i32,
                elapsed_ms: ms_since(t),
            });
            // The three files are not needed any more (and are never read again).
            if let Source::Offline { dir, name } = &sel.source {
                warnings.extend(dir.consume(name));
            }
        }
        ctx.check_cancelled()
            .map_err(|e| Fail::new(ProgressStage::ImageImport, e))?;

        ctx.progress
            .stage(ProgressStage::Launch, "starting the desktop");
        let spec = self
            .spec
            .clone()
            .with_image(ImageSource::LocalFingerprint(entry.sha256.clone()));
        let mut cb = self.callback();
        let report = finish_prebuilt(client, self.plan, &spec, self.secrets, &mut cb)
            .await
            .map_err(|e| {
                let in_post = self.in_post.load(std::sync::atomic::Ordering::SeqCst);
                let stage = if in_post {
                    ProgressStage::Post
                } else {
                    stage_of(&e)
                };
                Fail {
                    stage,
                    err: provision_err(e),
                    before_post: !in_post,
                }
            })?;
        Ok(Provisioned {
            report,
            path: pb::PathTaken::Prebuilt,
            reason: reason.clone(),
            image: Some(pb::ImageInfo {
                build_id: entry.build_id.clone(),
                created_unix: entry.created,
                size: entry.size,
                release_bps: sel.release_bps.unwrap_or(0),
                mirror_bps: sel.mirror_bps.unwrap_or(0),
            }),
            image_timings,
            warnings,
            delete_after_ready: Some(entry.sha256),
        })
    }

    /// Runs what `decision` says, with the fall back of ipc.md 6.5 step 9.
    async fn provision(
        &self,
        decision: Decision,
        auto: bool,
        request_start: Instant,
    ) -> Result<Provisioned, CmdError> {
        let (mut sel, reason) = match decision {
            Decision::Build(reason) => return self.build(reason).await,
            Decision::Prebuilt(sel, reason) => (sel, reason),
        };
        let offline = matches!(sel.source, Source::Offline { .. });
        let fail = match self.prebuilt(&mut sel, &reason).await {
            Ok(p) => return Ok(p),
            Err(f) => f,
        };
        // In `AUTO`, a failure before the post stage begins falls back to a build, if enough of the
        // request's time is left. After it began, a build would run the same post stage; an
        // offline image and `PREBUILT` never fall back; a cancel or a deadline is not a failure.
        let cfg = &self.d.cfg.image;
        let remaining = cfg.create_deadline.saturating_sub(request_start.elapsed());
        let cancelled = matches!(
            fail.err.code,
            pb::ErrorCode::Cancelled | pb::ErrorCode::DeadlineExceeded
        ) || self.ctx.cancel.reason().is_some();
        if !(auto && !offline && fail.before_post && !cancelled)
            || remaining < cfg.fallback_min_remaining
        {
            return Err(fail.err);
        }
        let text = format!(
            "building on the server: prebuilt image failed at {} ({})",
            stage_name(fail.stage),
            fail.err.message
        );
        self.d.audit_notice(&format!(
            "prebuilt image failed at {}; building on the server",
            stage_name(fail.stage)
        ));
        // Undo what the attempt did: the half-made instance, and the image if it was imported.
        for op in self.client.in_flight_operations() {
            let _ = self.client.cancel_operation(&op).await;
        }
        let cleanup = self.d.incus.scoped();
        if !self.d.destroy_unfinished(&cleanup, self.name).await {
            return Err(fail.err);
        }
        cache::purge(self.d, &cleanup, &sel.entry.sha256).await;
        self.build(Reason::new(ImageReason::FellBack, &text)).await
    }
}

/// `CreateDesktop` (class S).
pub async fn create_desktop<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    r: pb::CreateDesktopRequest,
) -> Result<Reply, CmdError> {
    let request_start = Instant::now();
    let id = r.desktop_id.clone();
    // Parse every argument into a typed value first.
    let image_mode = pb::ImageMode::try_from(r.image_mode).unwrap_or(pb::ImageMode::Unspecified);
    if let Some(f) = &r.image_file {
        if ctx.role != Role::Admin {
            return Err(CmdError::denied("create_desktop.image_file: Admin only"));
        }
        // The wire decoder checks this too; a name is never a path (ipc.md 6.5).
        if !hx_ipc::privd::is_valid_image_file_name(f) {
            return Err(CmdError::invalid("create_desktop.image_file"));
        }
        if image_mode == pb::ImageMode::Build {
            return Err(CmdError::invalid(
                "create_desktop.image_file: an offline image cannot be combined with image_mode BUILD",
            ));
        }
    }
    let auto = r.image_file.is_none()
        && matches!(image_mode, pb::ImageMode::Unspecified | pb::ImageMode::Auto);
    let recipe = recipe_from_pb(r.distro, r.desktop, r.preset)?;
    let username = Username::new(&r.username)
        .map_err(|e| CmdError::invalid(format!("create_desktop.username: {e}")))?;
    let settings = build_settings(
        r.settings
            .as_ref()
            .unwrap_or(&pb::DesktopSettings::default()),
        &d.cfg.zoneinfo_dir,
    )?;
    if r.docker && !r.docker_isolation_acknowledged {
        return Err(CmdError::invalid(
            "create_desktop.docker_isolation_acknowledged",
        ));
    }
    let password = ctx
        .take_secret(0)
        .ok_or_else(|| CmdError::invalid("create_desktop: slot 0 (USER_PASSWORD) missing"))?;
    let secrets = Secrets::none()
        .with_user_password(
            std::str::from_utf8(password.expose())
                .map_err(|_| CmdError::invalid("create_desktop: slot 0 is not UTF-8"))?,
        )
        .map_err(|_| CmdError::invalid("create_desktop: slot 0"))?;
    drop(password);

    let _g = d.lock_desktop(ctx, &id, true).await?;
    let name = d.instance_name(&id);
    let client = d.incus.scoped();
    ctx.progress
        .stage(ProgressStage::Preflight, "checking the host");

    // An existing instance: converge, or clean up an unfinished one.
    if let Some(inst) = client.get_instance(&name).await? {
        if !hx_provision::incus::instance_is_marked(&inst.config) {
            return Err(CmdError::precondition(
                ErrorDetail::DesktopExists,
                "an instance with this name exists and is not a hash-xcreen desktop",
            ));
        }
        let meta = crate::privd::daemon::DesktopMeta::from_config(&inst);
        if meta.state == "ready" {
            if meta.recipe == recipe_text(recipe) && meta.username == username.as_str() {
                let registered = d.read_state(|s| s.desktops.contains_key(&id));
                if registered {
                    // A resume: nothing to do, and the password stays as it is.
                    return Ok(response::Result::CreateDesktop(pb::CreateDesktopResult {
                        desktop_id: id,
                        path_taken: pb::PathTaken::Build as i32,
                        reason: "the desktop already exists with these arguments".into(),
                        reason_code: ImageReason::Existing as i32,
                        ..Default::default()
                    }));
                }
                // A desktop kept by `uninstall --keep-desktop`: the instance survived, privd's
                // registry and the session link did not. Adopt it.
                return adopt_kept_desktop(d, ctx, &client, &id, &name, recipe, &username, secrets)
                    .await;
            }
            return Err(CmdError::precondition(
                ErrorDetail::DesktopExists,
                "a desktop with this id exists with other arguments",
            ));
        }
        // creating or failed: it holds no user data yet.
        d.run_cancellable(ctx, &client, Some(&id), async {
            hx_provision::destroy_instance(&client, &name).await
        })
        .await?;
    } else {
        let others = d.read_state(|s| s.desktops.keys().filter(|k| **k != id).count());
        if others >= d.cfg.max_desktops {
            return Err(CmdError::precondition(
                ErrorDetail::DesktopExists,
                "the desktop limit is reached",
            ));
        }
    }

    // Host headroom: free pool space, and the bounds for the limits.
    let bounds = host_bounds(d)?;
    let (total, free) = d.probe.pool_space(&d.cfg.naming.pool).ok_or_else(|| {
        CmdError::precondition(ErrorDetail::Pool, "the storage pool cannot be read")
    })?;
    if free < MIN_FREE_GIB * GIB || free.saturating_mul(100) < total.saturating_mul(15) {
        return Err(CmdError::precondition(
            ErrorDetail::Pool,
            "the pool needs at least 8 GiB and 15% free",
        )
        .at_stage(ProgressStage::Preflight));
    }
    let (cpu, memory_mib, disk_gib) = resolve_limits(r.limits.as_ref(), &bounds, total / GIB)?;

    let plan = d
        .catalog
        .resolve_with(recipe, &[], Some(&username), &settings)
        .map_err(|e| CmdError::internal(sanitize_text(&e.to_string(), 200)))?;
    let spec = DesktopSpec::for_plan(
        name.clone(),
        d.cfg.naming.clone(),
        &plan,
        Limits {
            cpu: Some(cpu),
            memory_mib: Some(memory_mib),
            disk_gib: Some(disk_gib),
            processes: None,
        },
    );

    // The path (ipc.md 6.5 step 3): before anything is registered, so that a `PREBUILT` request
    // that cannot be served leaves nothing behind.
    let decision = choose(
        d,
        ctx,
        &client,
        &ChooseRequest {
            mode: image_mode,
            image_file: r.image_file.as_deref(),
            recipe,
            pool: (total, free),
        },
    )
    .await?;
    // Every recorded image that is not the selected one goes.
    let keep = match &decision {
        Decision::Prebuilt(sel, _) => Some(sel.entry.sha256.clone()),
        Decision::Build(_) => None,
    };
    cache::cleanup_unselected(d, &client, keep.as_deref()).await;
    d.register_desktop(&id)?;

    let progress = ctx.progress.clone();
    let started = Instant::now();
    // Set once the post stage (the one that handles the password) has begun.
    let in_post = std::sync::atomic::AtomicBool::new(false);
    let shared_ctx: &Ctx = ctx;
    let work = async {
        let env = Env {
            d,
            ctx: shared_ctx,
            client: &client,
            plan: &plan,
            spec: &spec,
            secrets: &secrets,
            in_post: &in_post,
            name: &name,
        };
        let prov = env.provision(decision, auto, request_start).await?;
        let report = &prov.report;
        let mut warnings = warnings_of(report);
        warnings.extend(prov.warnings.iter().cloned());

        let meta: std::collections::BTreeMap<String, String> = [
            ("user.hx.username", username.as_str().to_string()),
            ("user.hx.recipe", recipe_text(recipe)),
            ("user.hx.created", d.now().to_string()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        client
            .patch_instance_config(&name, &meta)
            .await
            .map_err(|e| CmdError::from(e).at_stage(ProgressStage::Post))?;

        progress.stage(ProgressStage::Session, "linking the session");
        provision_link_inner(d, shared_ctx, &client, &id, &name)
            .await
            .map_err(|e| e.at_stage(ProgressStage::Session))?;
        match install_inner(d, shared_ctx, &client, &id, &name, &recipe_text(recipe))
            .await
            .map_err(|e| e.at_stage(ProgressStage::Session))?
        {
            Some(_) => {}
            None => warnings.push(
                "the hx-session package is not installed on the host; run InstallSession once it is"
                    .to_string(),
            ),
        }

        let docker = if r.docker {
            progress.stage(ProgressStage::Docker, "enabling Docker");
            // Recorded before nesting goes on, so the isolation check sees it as intended.
            client
                .patch_instance_config(
                    &name,
                    &[("user.hx.docker_ack".to_string(), d.now().to_string())]
                        .into_iter()
                        .collect(),
                )
                .await
                .map_err(|e| CmdError::from(e).at_stage(ProgressStage::Docker))?;
            Some(
                enable_flow(
                    d,
                    shared_ctx,
                    &id,
                    &name,
                    &recipe_text(recipe),
                    username.as_str(),
                )
                .await?,
            )
        } else {
            None
        };

        // `ready` is written last, after every step above succeeded.
        client
            .patch_instance_config(
                &name,
                &[("user.hx.state".to_string(), "ready".to_string())]
                    .into_iter()
                    .collect(),
            )
            .await
            .map_err(CmdError::from)?;
        // The desktop no longer needs the imported image (on btrfs the instance does not depend
        // on it): delete it, best effort.
        if let Some(fp) = &prov.delete_after_ready {
            cache::purge(d, &client, fp).await;
        }
        progress.emit(ProgressStage::Done, 0, 0, "done", 100, true);
        warnings.truncate(16);
        let mut timings = prov.image_timings.clone();
        if report.build.is_some() {
            timings.push(pb::StageTiming {
                stage: ProgressStage::Build as i32,
                elapsed_ms: sum_ms(&report.build),
            });
        }
        timings.push(pb::StageTiming {
            stage: ProgressStage::Post as i32,
            elapsed_ms: sum_ms(&report.post),
        });
        timings.push(pb::StageTiming {
            stage: ProgressStage::Done as i32,
            elapsed_ms: ms_since(started),
        });
        d.audit_notice(&format!(
            "create_desktop: path={} reason_code={} build_id={}",
            if prov.path == pb::PathTaken::Prebuilt {
                "prebuilt"
            } else {
                "build"
            },
            prov.reason.code.as_str_name(),
            prov.image.as_ref().map_or("-", |i| i.build_id.as_str()),
        ));
        Ok::<_, CmdError>(pb::CreateDesktopResult {
            desktop_id: id.clone(),
            path_taken: prov.path as i32,
            reason: prov.reason.text.clone(),
            timings,
            warnings,
            docker,
            reason_code: prov.reason.code as i32,
            image: prov.image.clone(),
        })
    };
    let mut work = Box::pin(work);
    let outcome = tokio::select! {
        r = &mut work => r,
        reason = ctx.cancel.cancelled() => {
            if in_post.load(std::sync::atomic::Ordering::SeqCst) {
                // The post stage is a secret-carrying section and is shielded (ipc.md 4): keep
                // polling it to its end, so that its sweep of the work directory runs, and only
                // then clean up and answer. Its own timeouts bound it.
                let _ = (&mut work).await;
            }
            Err(reason.error())
        },
    };
    match outcome {
        Ok(res) => Ok(response::Result::CreateDesktop(res)),
        Err(e) => {
            // Cancelling an exec operation is refused by Incus 6.0.0, so end them the way the
            // contract says: cancel what can be cancelled, force-stop and delete the instance
            // (which ends the rest), then wait for the operations and clean up the record.
            drop(work);
            for op in client.in_flight_operations() {
                let _ = client.cancel_operation(&op).await;
            }
            let cleanup = d.incus.scoped();
            let destroyed = d.destroy_unfinished(&cleanup, &name).await;
            let ended = d.end_operations(&client, Some(&id)).await;
            if destroyed {
                let _ = d.unregister_desktop(&id);
            }
            ended?;
            Err(e)
        }
    }
}

/// Adopts a ready desktop that `uninstall --keep-desktop` left behind: registers it again,
/// **sets the password given in this request** (so that the verifier the installer writes next
/// matches the Linux account), and provisions the session link and the session again.
///
/// The password change is shielded like `SetUserPassword` (`change_user_password` runs as one
/// detached task that is always awaited to the end). On a failure the desktop is unregistered
/// again, so a retry adopts it afresh.
#[allow(clippy::too_many_arguments)]
async fn adopt_kept_desktop<T: Transport + Clone + 'static>(
    d: &Daemon<T>,
    ctx: &mut Ctx,
    client: &hx_provision::incus::Client<T>,
    id: &str,
    name: &str,
    recipe: hx_provision::RecipeId,
    username: &hx_provision::Username,
    secrets: Secrets,
) -> Result<response::Result, CmdError> {
    let others = d.read_state(|s| s.desktops.keys().filter(|k| *k != id).count());
    if others >= d.cfg.max_desktops {
        return Err(CmdError::precondition(
            ErrorDetail::DesktopExists,
            "the desktop limit is reached",
        ));
    }
    d.register_desktop(id)?;
    let progress = ctx.progress.clone();
    let result: Result<Vec<String>, CmdError> = async {
        progress.stage(
            ProgressStage::Post,
            "setting the password of the kept desktop",
        );
        match hx_provision::password::change_user_password(&d.incus, name, username, secrets, false)
            .await
            .map_err(|e| CmdError::from(e).at_stage(ProgressStage::Post))?
        {
            hx_provision::password::PasswordChange::Changed => {}
            _ => {
                return Err(CmdError::internal(
                    "the password of the kept desktop could not be set",
                )
                .at_stage(ProgressStage::Post));
            }
        }
        let mut warnings = Vec::new();
        progress.stage(ProgressStage::Session, "linking the session");
        provision_link_inner(d, ctx, client, id, name)
            .await
            .map_err(|e| e.at_stage(ProgressStage::Session))?;
        if install_inner(d, ctx, client, id, name, &recipe_text(recipe))
            .await
            .map_err(|e| e.at_stage(ProgressStage::Session))?
            .is_none()
        {
            warnings.push(
                "the hx-session package is not installed on the host; run InstallSession once it is"
                    .to_string(),
            );
        }
        Ok(warnings)
    }
    .await;
    // Only now may the request end as cancelled; a completed password change stands.
    if let Some(reason) = ctx.cancel.reason() {
        return Err(reason.error());
    }
    match result {
        Ok(warnings) => {
            progress.emit(ProgressStage::Done, 0, 0, "done", 100, true);
            Ok(response::Result::CreateDesktop(pb::CreateDesktopResult {
                desktop_id: id.to_string(),
                path_taken: pb::PathTaken::Build as i32,
                reason: "adopted the existing desktop".into(),
                reason_code: ImageReason::Existing as i32,
                timings: Vec::new(),
                warnings,
                docker: None,
                image: None,
            }))
        }
        Err(e) => {
            let _ = d.unregister_desktop(id);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds() -> HostBounds {
        HostBounds {
            cpus: 8,
            ram_mib: 16_384,
            pool_free_gib: 100,
        }
    }

    #[test]
    fn omitted_limits_default_to_the_host_minus_the_reserve() {
        let (cpu, mem, disk) = resolve_limits(None, &bounds(), 100).unwrap();
        assert_eq!((cpu, mem, disk), (8, 12_288, 80));
    }

    #[test]
    fn given_limits_are_still_bounded() {
        let l = pb::Limits {
            cpu: 9,
            memory_mib: 4096,
            disk_gib: 20,
        };
        assert!(resolve_limits(Some(&l), &bounds(), 100).is_err());
        let l = pb::Limits {
            cpu: 2,
            memory_mib: 4096,
            disk_gib: 20,
        };
        assert_eq!(
            resolve_limits(Some(&l), &bounds(), 100).unwrap(),
            (2, 4096, 20)
        );
    }

    #[test]
    fn settings_are_validated_by_hx_provision() {
        let zi = std::path::Path::new("/usr/share/zoneinfo");
        let ok = pb::DesktopSettings {
            hostname: "desk-1".into(),
            timezone: String::new(),
            locale: "en_US.UTF-8".into(),
            keyboard: "us".into(),
        };
        assert!(build_settings(&ok, zi).is_ok());
        assert!(
            build_settings(&pb::DesktopSettings::default(), zi)
                .unwrap()
                .is_empty()
        );
        for bad in [
            pb::DesktopSettings {
                hostname: "bad name;".into(),
                ..Default::default()
            },
            pb::DesktopSettings {
                locale: "xx".into(),
                ..Default::default()
            },
            pb::DesktopSettings {
                keyboard: "$(x)".into(),
                ..Default::default()
            },
            pb::DesktopSettings {
                timezone: "../../etc/passwd".into(),
                ..Default::default()
            },
        ] {
            assert!(build_settings(&bad, zi).is_err(), "{bad:?}");
        }
    }
}
