//! `desktop`: create one desktop the way the agent would, on one of the two paths, and write its
//! facts for the equivalence check.
//!
//! - `--path build`: `build_on_server` (the base image, the build stage, the post stage, restart).
//! - `--path prebuilt --image F`: import the image file `F` with the streaming upload, then
//!   `finish_prebuilt` (post stage with the user rename, restart), then delete the image, as the
//!   agent does once the desktop is ready.
//!
//! Both paths use the same user, password and settings, so they are meant to end up identical.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use hx_provision::equiv::collect_facts;
use hx_provision::incus::{ImageSource, ImageUpload};
use hx_provision::orchestrate::{DesktopSpec, build_on_server, destroy_instance, finish_prebuilt};
use hx_provision::{Catalog, Secrets, Settings, Username};
use zeroize::Zeroizing;

use crate::args::{Parsed, Spec};
use crate::host::{
    DEFAULT_PREFIX, LONG, connect, desktop_name, fingerprint_of_alias, import_alias, limits,
    progress,
};
use crate::util::{CliError, default_plan, failed, read_bounded, recipe, sha256_file};

/// Options of `desktop`.
pub const SPEC: Spec = Spec {
    values: &[
        "recipe",
        "path",
        "image",
        "user",
        "password-file",
        "facts",
        "prefix",
        "pool-gib",
        "cpu",
        "memory-mib",
    ],
    lists: &[],
    flags: &["keep"],
    positionals: 0,
};

/// The settings both desktops are made with: a non-default value for each, so the equivalence
/// check also covers the post stage's settings steps.
fn ci_settings() -> Result<Settings, CliError> {
    let bad = |e: hx_provision::SettingsError| failed(format!("settings: {e}"));
    Settings::none()
        .with_timezone_in("Europe/Berlin", Path::new("/usr/share/zoneinfo"))
        .map_err(bad)?
        .with_locale("de_DE")
        .map_err(bad)?
        .with_keyboard("de+nodeadkeys")
        .map_err(bad)
}

/// The first line of the password file, without its line ending. Never printed.
fn read_password(path: &Path) -> Result<Zeroizing<String>, CliError> {
    let bytes = Zeroizing::new(read_bounded(path, 4096)?);
    let text =
        std::str::from_utf8(&bytes).map_err(|_| failed("the password file is not UTF-8 text"))?;
    let line = text.lines().next().unwrap_or_default();
    if line.is_empty() {
        return Err(failed("the password file is empty"));
    }
    Ok(Zeroizing::new(line.to_string()))
}

/// The unified image file for `--image`: a plain file, or the first part (`<file>.p0`) of a split
/// image, whose parts are joined into a temporary file next to it (returned so it can be removed).
fn unified_image(image: &Path) -> Result<(PathBuf, Option<PathBuf>), CliError> {
    let name = image.to_string_lossy();
    let Some(stem) = name.strip_suffix(".p0") else {
        return Ok((image.to_path_buf(), None));
    };
    let joined = PathBuf::from(format!("{stem}.joined"));
    let mut out =
        File::create(&joined).map_err(|e| failed(format!("create {}: {e}", joined.display())))?;
    let mut buf = vec![0u8; 1 << 20];
    for i in 0.. {
        let part = PathBuf::from(format!("{stem}.p{i}"));
        let Ok(mut f) = File::open(&part) else {
            if i == 0 {
                return Err(failed(format!("open {}: no such part", part.display())));
            }
            break;
        };
        loop {
            let n = f
                .read(&mut buf)
                .map_err(|e| failed(format!("read {}: {e}", part.display())))?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])
                .map_err(|e| failed(format!("write {}: {e}", joined.display())))?;
        }
    }
    out.sync_all().map_err(|e| failed(e.to_string()))?;
    Ok((joined.clone(), Some(joined)))
}

pub async fn run(p: &Parsed) -> Result<(), CliError> {
    let id = recipe(p.require("recipe")?)?;
    let path = p.require("path")?;
    if path != "build" && path != "prebuilt" {
        return Err(CliError::Usage(
            "--path must be `build` or `prebuilt`".into(),
        ));
    }
    let image = match (path, p.get("image")) {
        ("prebuilt", None) => {
            return Err(CliError::Usage("--path prebuilt needs --image FILE".into()));
        }
        ("build", Some(_)) => {
            return Err(CliError::Usage(
                "--image only goes with --path prebuilt".into(),
            ));
        }
        (_, i) => i.map(PathBuf::from),
    };
    let user_name = p.require("user")?;
    let user = Username::new(user_name)
        .map_err(|e| CliError::Usage(format!("--user `{user_name}`: {e}")))?;
    let password = read_password(Path::new(p.require("password-file")?))?;
    let facts_out = PathBuf::from(p.require("facts")?);
    let prefix = p.get("prefix").unwrap_or(DEFAULT_PREFIX);
    let pool_gib = p.number("pool-gib")?.unwrap_or(40);
    let lim = limits(p.number("cpu")?, p.number("memory-mib")?);
    let keep = p.flag("keep");

    let plan = Catalog::embedded()
        .resolve_with(id, &[], Some(&user), &ci_settings()?)
        .map_err(|e| failed(format!("recipe does not resolve: {e}")))?;
    let secrets = Secrets::none()
        .with_user_password(&password)
        .map_err(|e| failed(format!("password: {e}")))?;

    let ctx = connect(prefix, pool_gib, Some(&default_plan(id)?)).await?;
    let c = &ctx.client;
    let name = desktop_name(prefix, path);
    let _ = destroy_instance(c, &name).await;
    let mut spec = DesktopSpec::for_plan(&name, ctx.naming.clone(), &plan, lim);
    if let Some(img) = &ctx.base_override {
        spec = spec.with_image(img.clone());
    }

    let started = Instant::now();
    let result: Result<(), CliError> = async {
        if let Some(image) = &image {
            run_prebuilt(&ctx, &plan, spec, &secrets, image, prefix).await
        } else {
            build_on_server(c, &plan, &spec, &secrets, &mut progress("build"))
                .await
                .map(drop)
                .map_err(|e| failed(format!("build_on_server: {e}")))
        }
    }
    .await;
    let facts = match result {
        Ok(()) => {
            eprintln!("desktop {name} is running after {:?}", started.elapsed());
            collect_facts(c, &name, user_name)
                .await
                .map_err(|e| failed(format!("collect_facts: {e}")))
        }
        Err(e) => Err(e),
    };
    if !keep {
        let _ = destroy_instance(c, &name).await;
    }
    let facts = facts?;
    let json = serde_json::to_vec_pretty(&facts).map_err(|e| failed(e.to_string()))?;
    std::fs::write(&facts_out, json)
        .map_err(|e| failed(format!("write {}: {e}", facts_out.display())))?;
    eprintln!(
        "facts of {name} ({} packages, {} /etc entries) written to {}; total {:?}",
        facts.packages.len(),
        facts.etc.len(),
        facts_out.display(),
        started.elapsed()
    );
    Ok(())
}

async fn run_prebuilt(
    ctx: &crate::host::HostCtx,
    plan: &hx_provision::Plan,
    spec: DesktopSpec,
    secrets: &Secrets,
    image: &Path,
    prefix: &str,
) -> Result<(), CliError> {
    let c = &ctx.client;
    let (file, joined) = unified_image(image)?;
    let result = async {
        let (fp, len) = sha256_file(&file)?;
        eprintln!("image {} is {len} bytes, sha256 {fp}", file.display());
        let alias = import_alias(prefix);
        // An image left by an earlier run would make the import conflict.
        if let Some(old) = fingerprint_of_alias(c, &alias).await? {
            let _ = c.delete_image(&old).await;
        }
        let t = Instant::now();
        let f = File::open(&file).map_err(|e| failed(format!("open {}: {e}", file.display())))?;
        c.import_image(
            ImageUpload {
                file: f,
                len,
                fingerprint: fp.clone(),
            },
            LONG,
        )
        .await
        .map_err(|e| failed(format!("import_image: {e}")))?;
        c.create_image_alias(&alias, &fp)
            .await
            .map_err(|e| failed(format!("create_image_alias: {e}")))?;
        eprintln!("imported in {:?}", t.elapsed());
        let spec = spec.with_image(ImageSource::LocalFingerprint(fp.clone()));
        let r = finish_prebuilt(c, plan, &spec, secrets, &mut progress("post"))
            .await
            .map(drop)
            .map_err(|e| failed(format!("finish_prebuilt: {e}")));
        // Once the desktop exists the image is not needed (btrfs); the agent deletes it too.
        let _ = c.delete_image(&fp).await;
        r
    }
    .await;
    if let Some(j) = joined {
        let _ = std::fs::remove_file(j);
    }
    result
}
