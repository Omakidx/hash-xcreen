//! `build-image`: build the recipe's build stage into a container, seal it, publish it as a
//! zstd-compressed unified Incus image, export it, check the fingerprint, split it when it is too
//! large for one release asset, and write `entry.json`.

use std::path::{Path, PathBuf};
use std::time::Instant;

use hx_provision::images::{
    self, COMPRESSIONS, FORMAT_UNIFIED, ImageEntry, ImagesManifest, MAX_IMAGE_BYTES,
    MAX_PART_BYTES, MAX_PARTS, MAX_UNPACKED_BYTES, Part,
};
use hx_provision::orchestrate::{DesktopSpec, build_image, destroy_instance};
use hx_provision::plan::ImageRef;

use crate::args::{Parsed, Spec};
use crate::host::{
    builder_name, connect, fingerprint_of_alias, incus, limits, progress, publish_alias,
};
use crate::util::{
    CliError, default_plan, failed, now_unix, recipe, sha256_file, split_file, valid_build_id,
};

/// Options of `build-image`.
pub const SPEC: Spec = Spec {
    values: &[
        "recipe",
        "prefix",
        "build-id",
        "out",
        "min-agent",
        "pool-gib",
        "cpu",
        "memory-mib",
    ],
    lists: &[],
    flags: &[],
    positionals: 0,
};

/// The zstd frame magic number, little endian.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Name of the entry file written next to the image.
pub const ENTRY_FILE: &str = "entry.json";

/// The architecture this tool builds for.
pub const ARCH: &str = "x86_64";

pub async fn run(p: &Parsed) -> Result<(), CliError> {
    let id = recipe(p.require("recipe")?)?;
    let prefix = p.get("prefix").unwrap_or(crate::host::DEFAULT_PREFIX);
    let build_id = p.require("build-id")?;
    if !valid_build_id(build_id) {
        return Err(CliError::Usage(
            "--build-id must look like 20261123.1 (YYYYMMDD.N)".into(),
        ));
    }
    let out = PathBuf::from(p.require("out")?);
    let min_agent = p.get("min-agent").unwrap_or(env!("CARGO_PKG_VERSION"));
    let pool_gib = p.number("pool-gib")?.unwrap_or(40);
    let lim = limits(p.number("cpu")?, p.number("memory-mib")?);
    prepare_out(&out)?;

    let plan = default_plan(id)?;
    let digest = plan.build_digest();
    let ImageRef::Remote { alias: base_alias } = &plan.base_image else {
        return Err(failed("the recipe's base image is not a remote alias"));
    };
    let base_alias = base_alias.clone();
    eprintln!(
        "building {} (digest {digest}) as build {build_id}",
        images::recipe_name(id)
    );

    let ctx = connect(prefix, pool_gib, Some(&plan)).await?;
    let c = &ctx.client;
    let builder = builder_name(prefix);
    let alias = publish_alias(prefix);
    // Leftovers of an earlier run on the same host.
    let _ = destroy_instance(c, &builder).await;
    let _ = incus(&["image", "delete", &alias]).await;

    let mut spec = DesktopSpec::for_plan(&builder, ctx.naming.clone(), &plan, lim);
    if let Some(img) = &ctx.base_override {
        spec = spec.with_image(img.clone());
    }
    let started = Instant::now();
    let built = build_image(c, &plan, &spec, &mut progress("image")).await;
    let report = match built {
        Ok(r) => r,
        Err(e) => {
            let _ = destroy_instance(c, &builder).await;
            return Err(failed(format!("build_image: {e}")));
        }
    };
    eprintln!(
        "build stage, seal and stop done in {:?} ({} optional steps warned)",
        started.elapsed(),
        report.warnings.len()
    );

    // Publish, export and describe; the builder and the published copy are removed on every path.
    let result = publish_and_export(
        &ctx.client,
        &builder,
        &alias,
        &out,
        &images::file_name(id, build_id),
    )
    .await;
    let _ = incus(&["image", "delete", &alias]).await;
    let _ = destroy_instance(c, &builder).await;
    let exported = result?;

    let now = now_unix();
    let entry = ImageEntry {
        recipe: images::recipe_name(id),
        distro: id.distro.as_str().into(),
        desktop: id.desktop.as_str().into(),
        preset: id.preset.as_str().into(),
        recipe_digest: digest,
        build_id: build_id.into(),
        created: now,
        min_agent: min_agent.into(),
        format: FORMAT_UNIFIED.into(),
        compression: "zstd".into(),
        base_alias,
        file: images::file_name(id, build_id),
        size: exported.size,
        sha256: exported.sha256,
        unpacked_size: if exported.unpacked == 0 {
            // Incus did not report the disk usage: assume a conservative compression ratio.
            exported.size.saturating_mul(4)
        } else {
            exported.unpacked
        }
        .clamp(exported.size, MAX_UNPACKED_BYTES),
        parts: exported.parts,
    };
    check_entry(&entry, now)?;
    let json = serde_json::to_string_pretty(&entry).map_err(|e| failed(e.to_string()))?;
    std::fs::write(out.join(ENTRY_FILE), format!("{json}\n"))
        .map_err(|e| failed(format!("write {ENTRY_FILE}: {e}")))?;
    println!("{json}");
    eprintln!(
        "image {} is {} bytes in {} part(s); total {:?}",
        entry.file,
        entry.size,
        entry.parts.len(),
        started.elapsed()
    );
    Ok(())
}

/// The output directory must be new or empty, so a stale file cannot end up in an entry.
fn prepare_out(out: &Path) -> Result<(), CliError> {
    std::fs::create_dir_all(out).map_err(|e| failed(format!("create {}: {e}", out.display())))?;
    let n = std::fs::read_dir(out)
        .map_err(|e| failed(format!("read {}: {e}", out.display())))?
        .count();
    if n != 0 {
        return Err(CliError::Usage(format!(
            "--out {} must be empty",
            out.display()
        )));
    }
    Ok(())
}

/// Run the manifest rules over the entry before writing it.
pub fn check_entry(entry: &ImageEntry, now: u64) -> Result<(), CliError> {
    let m = ImagesManifest {
        schema: images::SCHEMA,
        kind: images::KIND.into(),
        arch: ARCH.into(),
        timestamp: now.max(entry.created),
        images: vec![entry.clone()],
    };
    m.validate(ARCH, now)
        .map_err(|e| failed(format!("the entry is not a valid manifest entry: {e}")))
}

/// What the export produced.
struct Exported {
    size: u64,
    sha256: String,
    unpacked: u64,
    parts: Vec<Part>,
}

async fn publish_and_export(
    c: &hx_provision::incus::Client<hx_provision::incus::UnixTransport>,
    builder: &str,
    alias: &str,
    out: &Path,
    file: &str,
) -> Result<Exported, CliError> {
    let t = Instant::now();
    incus(&[
        "publish",
        builder,
        "--alias",
        alias,
        "--compression",
        COMPRESSIONS[0],
    ])
    .await?;
    let fp = fingerprint_of_alias(c, alias)
        .await?
        .ok_or_else(|| failed("the published image has no alias"))?;
    eprintln!("published {fp} in {:?}", t.elapsed());
    let unpacked = unpacked_size(builder).await;

    let tmp = out.join(".export");
    std::fs::create_dir(&tmp).map_err(|e| failed(format!("create {}: {e}", tmp.display())))?;
    let t = Instant::now();
    incus(&["image", "export", &fp, &tmp.to_string_lossy()]).await?;
    let mut files: Vec<PathBuf> = std::fs::read_dir(&tmp)
        .map_err(|e| failed(format!("read {}: {e}", tmp.display())))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    if files.len() != 1 {
        return Err(failed(format!(
            "the export is not a single unified file: {files:?}"
        )));
    }
    let exported = files.remove(0);
    let (sha, size) = sha256_file(&exported)?;
    eprintln!("exported {size} bytes in {:?}, sha256 {sha}", t.elapsed());
    if sha != fp {
        return Err(failed(format!(
            "the exported file's sha256 {sha} is not the Incus fingerprint {fp}"
        )));
    }
    check_zstd(&exported)?;
    if !(1..=MAX_IMAGE_BYTES).contains(&size) {
        return Err(failed(format!(
            "the image is {size} bytes; the manifest allows 1 byte to 4 GiB"
        )));
    }
    let parts = if size <= MAX_PART_BYTES {
        std::fs::rename(&exported, out.join(file))
            .map_err(|e| failed(format!("move the image: {e}")))?;
        vec![Part {
            size,
            sha256: sha.clone(),
        }]
    } else {
        let parts = split_file(&exported, out, file, MAX_PART_BYTES)?;
        std::fs::remove_file(&exported).map_err(|e| failed(format!("remove the export: {e}")))?;
        if parts.len() > MAX_PARTS {
            return Err(failed(format!(
                "the image needs {} parts; at most {MAX_PARTS} are allowed",
                parts.len()
            )));
        }
        eprintln!("split into {} parts", parts.len());
        parts
    };
    let _ = std::fs::remove_dir(&tmp);
    Ok(Exported {
        size,
        sha256: sha,
        unpacked,
        parts,
    })
}

/// The file must be a zstd stream, as the entry's `compression` claims.
fn check_zstd(path: &Path) -> Result<(), CliError> {
    use std::io::Read;
    let mut magic = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .map_err(|e| failed(format!("read {}: {e}", path.display())))?;
    if magic == ZSTD_MAGIC {
        Ok(())
    } else {
        Err(failed(
            "the exported image is not a zstd stream (incus publish --compression zstd)",
        ))
    }
}

/// Bytes the builder's root disk uses (what the image takes once unpacked); 0 when Incus does not
/// say, which the caller replaces by the file size.
async fn unpacked_size(builder: &str) -> u64 {
    let Ok(text) = incus(&["query", &format!("/1.0/instances/{builder}/state")]).await else {
        return 0;
    };
    serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v["disk"]["root"]["usage"].as_u64())
        .unwrap_or(0)
}
