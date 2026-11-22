//! `--image-file <abs>`: an offline prebuilt desktop image (design 1D, C10; docs/architecture.md
//! 4.3, 5.2 and 5.3).
//!
//! Two halves, both here so that the checks and the copy cannot drift apart:
//!
//! * [`preflight`] (read-only, in stage `preflight`): the file is opened `O_NOFOLLOW|O_NONBLOCK`
//!   and must be a regular file of at most 4 GiB with the signed manifest
//!   (`images-manifest-x86_64.json`) and its `.minisig` beside it. The signature, the manifest's
//!   rules, the entry that matches this agent's recipe, and the file's size and SHA-256 are
//!   verified with privd's own code ([`ImageKeys`], [`verify_manifest`], `ImagesManifest::select`),
//!   so what the installer accepts is what privd would accept. A failure here is exit 10; a file
//!   that is not usable at all (missing, a symlink, too big) or too little disk is exit 9.
//! * [`stage_into_import`] (stage `desktop`): the three files are copied into
//!   `/var/lib/hx/import/` (root, 0700) for privd, which reads them with `openat2`, requires link
//!   count 1 and root ownership, imports the image and unlinks all three. Each copy goes to an
//!   `O_EXCL` temporary name through the directory descriptor and is `renameat`'d into place only
//!   after it was re-hashed while copying and found identical to what preflight verified, so a
//!   file that changed between the two stages is refused and a half-copied file never has a final
//!   name.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Mode, OFlags};
use sha2::{Digest, Sha256};

use super::ctx::Ctx;
use super::error::{InstallError, Result};
use super::fsx::{ensure_dir, sha256_hex};
use super::paths;
use crate::cli::text::{hex, peer};
use crate::privd::image::choose::verify_manifest;
use hx_provision::images::{
    MAX_IMAGE_BYTES, MAX_MANIFEST_BYTES, manifest_file_name, recipe_by_name, recipe_name,
};

/// The only architecture of this release (preflight enforces it).
pub const ARCH: &str = "x86_64";
/// Largest signature file (privd's limit).
const MAX_SIG_BYTES: u64 = 16 * 1024;
const GIB: u64 = 1 << 30;

/// What preflight verified: the three files and the facts the copy re-checks.
#[derive(Debug, Clone)]
pub struct Verified {
    /// The image file as given.
    pub image: PathBuf,
    /// Its base name (what `CreateDesktop.image_file` carries).
    pub name: String,
    /// The signed manifest beside it.
    pub manifest_path: PathBuf,
    /// Its signature.
    pub sig_path: PathBuf,
    /// The manifest's bytes as verified.
    pub manifest: Vec<u8>,
    /// The signature's bytes as verified.
    pub sig: Vec<u8>,
    /// The image's size, equal to the signed entry's.
    pub size: u64,
    /// The image's SHA-256, equal to the signed entry's.
    pub sha256: String,
    /// The entry's build id (for messages).
    pub build_id: String,
}

fn open_regular(path: &Path) -> std::result::Result<(File, u64), String> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        rustix::io::Errno::NOENT => "does not exist".to_owned(),
        rustix::io::Errno::LOOP => "is a symbolic link (give the real file)".to_owned(),
        rustix::io::Errno::ACCESS | rustix::io::Errno::PERM => "cannot be read".to_owned(),
        other => format!("cannot be opened ({})", other.kind()),
    })?;
    let f = File::from(fd);
    let m = f.metadata().map_err(|_| "cannot be examined".to_owned())?;
    if !m.is_file() {
        return Err("is not a regular file".into());
    }
    Ok((f, m.len()))
}

fn read_bounded(path: &Path, limit: u64) -> std::result::Result<Vec<u8>, String> {
    let (f, len) = open_regular(path)?;
    if len > limit {
        return Err(format!("is larger than {limit} bytes"));
    }
    let mut v = Vec::new();
    f.take(limit + 1)
        .read_to_end(&mut v)
        .map_err(|_| "cannot be read".to_owned())?;
    if v.len() as u64 > limit {
        return Err(format!("is larger than {limit} bytes"));
    }
    Ok(v)
}

fn sha256_of_file(f: &mut File, expect_len: u64) -> std::io::Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let n = match f.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > expect_len {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

/// The bytes of free space `/var/lib` needs for an image of `size` bytes: the copy in the import
/// directory, privd's staging copy and Incus's copy (docs/architecture.md 5.2), plus 2 GiB.
pub fn needed_bytes(size: u64) -> u64 {
    size.saturating_mul(3).saturating_add(2 * GIB)
}

/// Checks `--image-file` (read-only). `bad` collects the failures that are exit 9; a returned
/// error is exit 10 (verification). `Ok(None)` means `bad` is not empty.
pub fn preflight(
    ctx: &mut Ctx<'_>,
    given: &str,
    bad: &mut Vec<String>,
) -> Result<Option<Verified>> {
    let image = PathBuf::from(given);
    let name = image
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_owned();
    if !hx_ipc::privd::is_valid_image_file_name(&name) {
        bad.push(
            "--image-file: the file name must be 1 to 128 letters, digits, '.', '_' or '-', starting with a letter or digit"
                .into(),
        );
        return Ok(None);
    }
    let dir = image.parent().unwrap_or_else(|| Path::new("/"));
    let manifest_path = dir.join(manifest_file_name(ARCH));
    let sig_path = dir.join(format!("{}.minisig", manifest_file_name(ARCH)));
    let shown = |p: &Path| peer(&p.to_string_lossy(), 120);

    let image_file = match open_regular(&image) {
        Ok((f, len)) if len <= MAX_IMAGE_BYTES => Some((f, len)),
        Ok(_) => {
            bad.push(format!(
                "--image-file {} is larger than 4 GiB, the most a prebuilt image can be",
                shown(&image)
            ));
            None
        }
        Err(why) => {
            bad.push(format!("--image-file {} {why}", shown(&image)));
            None
        }
    };
    let manifest = read_bounded(&manifest_path, MAX_MANIFEST_BYTES as u64);
    let sig = read_bounded(&sig_path, MAX_SIG_BYTES);
    for (p, r) in [(&manifest_path, &manifest), (&sig_path, &sig)] {
        if let Err(why) = r {
            bad.push(format!(
                "{} {why} (the signed manifest and its signature must sit beside the image)",
                shown(p)
            ));
        }
    }
    let (Some((mut file, size)), Ok(manifest), Ok(sig)) = (image_file, manifest, sig) else {
        return Ok(None);
    };

    // From here on a failure is a failed verification (exit 10).
    let keys = &ctx.image_keys;
    if keys.is_empty() {
        return Err(InstallError::verify(
            "this hx-agent embeds no image signing key, so no image file can be verified; nothing was changed",
        ));
    }
    let sig_text = String::from_utf8(sig.clone()).map_err(|_| {
        InstallError::verify("the manifest signature is not text; nothing was changed")
    })?;
    let now = (ctx.now)();
    let parsed = verify_manifest(keys, &manifest, &sig_text, ARCH, now).map_err(|why| {
        InstallError::verify(format!(
            "the image manifest did not verify ({why}); nothing was changed"
        ))
    })?;
    let recipe = recipe_by_name(&format!(
        "{}-xfce-{}",
        ctx.opts.distro,
        if ctx.opts.apps == "developer" {
            "developer"
        } else {
            "basic"
        }
    ))
    .ok_or_else(|| InstallError::internal("no recipe for these options"))?;
    let digest = hx_provision::Catalog::embedded()
        .resolve(recipe, &[])
        .map_err(|e| InstallError::internal(format!("cannot resolve the recipe: {e}")))?
        .build_digest();
    let entry = parsed
        .select(recipe, &digest, env!("CARGO_PKG_VERSION"))
        .ok_or_else(|| {
            InstallError::verify(format!(
                "no entry of the signed manifest is for `{}` and this agent (recipes are bound by digest); nothing was changed",
                recipe_name(recipe)
            ))
        })?
        .clone();
    if size != entry.size {
        return Err(InstallError::verify(format!(
            "the image is {size} bytes but the signed entry says {}; nothing was changed",
            entry.size
        )));
    }
    let sha256 = sha256_of_file(&mut file, size)
        .map_err(|_| InstallError::verify("the image file cannot be read to the end"))?;
    if sha256 != entry.sha256 {
        return Err(InstallError::verify(
            "the image does not match its signed SHA-256; nothing was changed",
        ));
    }
    if !entry.is_fresh(now) {
        let msg = format!(
            "the image {} is {} days old (accepted: you chose this file)",
            peer(&entry.build_id, 24),
            entry.age_secs(now) / 86_400
        );
        ctx.warn("preflight", &msg);
    }

    let need = needed_bytes(size);
    match ctx.probe.free_gib(&ctx.paths.at("/var/lib")) {
        Ok(g) if g >= need.div_ceil(GIB) => {}
        Ok(g) => bad.push(format!(
            "{g} GiB free on /var/lib; the image file needs {} GiB (three copies of {} MiB, plus 2 GiB)",
            need.div_ceil(GIB),
            size.div_ceil(1 << 20)
        )),
        Err(_) => bad.push("cannot read the free disk space of /var/lib".into()),
    }
    if !bad.is_empty() {
        return Ok(None);
    }
    Ok(Some(Verified {
        image,
        name,
        manifest_path,
        sig_path,
        manifest,
        sig,
        size,
        sha256,
        build_id: entry.build_id,
    }))
}

/// What a copy must equal.
enum Want<'a> {
    /// The image: size and SHA-256.
    Sha(&'a str),
    /// The manifest or signature: these exact bytes.
    Bytes(&'a [u8]),
}

fn random_suffix() -> Result<String> {
    let mut b = [0u8; 6];
    rustix::rand::getrandom(&mut b, rustix::rand::GetRandomFlags::empty())
        .map_err(|e| InstallError::internal(format!("no randomness: {e}")))?;
    Ok(hex(&b))
}

fn io_err(what: &str, e: impl std::fmt::Display) -> InstallError {
    InstallError::internal(format!("{what}: {e}"))
}

/// Copies `src` into the import directory as `name`: `O_EXCL` temporary, re-hash, `renameat`.
fn copy_one(
    dir: &rustix::fd::OwnedFd,
    src: &Path,
    name: &str,
    expect_len: u64,
    want: &Want<'_>,
) -> Result<()> {
    let (mut from, len) = open_regular(src).map_err(|why| {
        InstallError::verify(format!(
            "{} {why} now; it changed after the check",
            peer(&src.to_string_lossy(), 120)
        ))
    })?;
    if len != expect_len {
        return Err(InstallError::verify(format!(
            "{} changed size after the check ({len} bytes, was {expect_len})",
            peer(&src.to_string_lossy(), 120)
        )));
    }
    let tmp = format!(".{name}.{}.tmp", random_suffix()?);
    let fd = rustix::fs::openat(
        dir,
        tmp.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| io_err("cannot create a file in /var/lib/hx/import", e))?;
    let mut to = File::from(fd);
    let fail = |e: InstallError| {
        let _ = rustix::fs::unlinkat(dir, tmp.as_str(), AtFlags::empty());
        e
    };
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = match from.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(fail(io_err("cannot read the source", e.kind()))),
        };
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > expect_len {
            return Err(fail(InstallError::verify(format!(
                "{} grew while it was copied",
                peer(&src.to_string_lossy(), 120)
            ))));
        }
        h.update(&buf[..n]);
        if let Err(e) = to.write_all(&buf[..n]) {
            return Err(fail(io_err(
                "cannot write to /var/lib/hx/import (is the disk full?)",
                e.kind(),
            )));
        }
    }
    let digest = hex(&h.finalize());
    let same = total == expect_len
        && match want {
            Want::Sha(s) => digest == *s,
            Want::Bytes(b) => digest == sha256_hex(b),
        };
    if !same {
        return Err(fail(InstallError::verify(format!(
            "{} is not what was verified (it changed after the check); nothing was imported",
            peer(&src.to_string_lossy(), 120)
        ))));
    }
    if let Err(e) = to.sync_all() {
        return Err(fail(io_err("cannot sync the copy", e.kind())));
    }
    drop(to);
    rustix::fs::renameat(dir, tmp.as_str(), dir, name)
        .map_err(|e| fail(io_err("cannot move the copy into place", e)))?;
    Ok(())
}

/// Opens the import directory: made 0700 when missing; an existing one must be a real directory
/// (not a symlink) owned by this user and closed to others, as privd requires.
fn open_import_dir(ctx: &Ctx<'_>) -> Result<rustix::fd::OwnedFd> {
    let path = ctx.paths.at(paths::IMPORT_DIR);
    ensure_dir(&path, 0o700)?;
    let fd = rustix::fs::open(
        &path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| io_err("cannot open /var/lib/hx/import", e))?;
    let st = rustix::fs::fstat(&fd).map_err(|e| io_err("cannot examine /var/lib/hx/import", e))?;
    if st.st_uid != rustix::process::geteuid().as_raw() || st.st_mode & 0o077 != 0 {
        return Err(InstallError::tool(
            "/var/lib/hx/import must be owned by root and closed to others (mode 0700); fix or remove it and run the same command again",
        ));
    }
    Ok(fd)
}

/// Copies the verified image, manifest and signature into `/var/lib/hx/import/`. The manifest
/// goes last: privd needs all three.
pub fn stage_into_import(ctx: &mut Ctx<'_>, v: &Verified) -> Result<()> {
    let dir = open_import_dir(ctx)?;
    copy_one(&dir, &v.image, &v.name, v.size, &Want::Sha(&v.sha256))?;
    let sig_name = format!("{}.minisig", manifest_file_name(ARCH));
    copy_one(
        &dir,
        &v.sig_path,
        &sig_name,
        v.sig.len() as u64,
        &Want::Bytes(&v.sig),
    )?;
    copy_one(
        &dir,
        &v.manifest_path,
        &manifest_file_name(ARCH),
        v.manifest.len() as u64,
        &Want::Bytes(&v.manifest),
    )?;
    rustix::fs::fsync(&dir).map_err(|e| io_err("cannot sync /var/lib/hx/import", e))?;
    ctx.progress.step(
        "desktop",
        &crate::cli::privd::ProgressLine {
            stage: "IMAGE_FILE".into(),
            index: 1,
            total: 1,
            step: format!(
                "copied image {} ({} MiB) for hx-privd",
                peer(&v.build_id, 24),
                v.size.div_ceil(1 << 20)
            ),
            percent: Some(100),
            ok: true,
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_dir(p: &Path) -> rustix::fd::OwnedFd {
        rustix::fs::open(
            p,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    fn names(p: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(p)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn a_copy_is_rehashed_and_only_then_given_its_name() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let data = vec![7u8; 3 << 20];
        std::fs::write(src.path().join("a.img"), &data).unwrap();
        let fd = open_dir(dst.path());
        let good = sha256_hex(&data);
        copy_one(
            &fd,
            &src.path().join("a.img"),
            "a.img",
            data.len() as u64,
            &Want::Sha(&good),
        )
        .unwrap();
        assert_eq!(names(dst.path()), ["a.img"]);
        assert_eq!(std::fs::read(dst.path().join("a.img")).unwrap(), data);

        // A digest that is not the file's: refused, the temporary is gone, the old copy stays.
        let e = copy_one(
            &fd,
            &src.path().join("a.img"),
            "a.img",
            data.len() as u64,
            &Want::Sha(&"0".repeat(64)),
        )
        .unwrap_err();
        assert_eq!(e.exit, crate::install::error::codes::VERIFY);
        assert_eq!(names(dst.path()), ["a.img"]);

        // A new name with a wrong digest never appears.
        let e = copy_one(
            &fd,
            &src.path().join("a.img"),
            "b.img",
            data.len() as u64,
            &Want::Sha(&"1".repeat(64)),
        );
        assert!(e.is_err());
        assert_eq!(names(dst.path()), ["a.img"]);
    }

    #[test]
    fn a_source_that_changed_size_or_is_not_a_regular_file_is_refused() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let fd = open_dir(dst.path());
        std::fs::write(src.path().join("a"), b"12345").unwrap();
        // Announced 4 bytes, the file has 5.
        assert!(copy_one(&fd, &src.path().join("a"), "a", 4, &Want::Bytes(b"1234")).is_err());
        // A symlink at the last component.
        std::os::unix::fs::symlink(src.path().join("a"), src.path().join("l")).unwrap();
        assert!(copy_one(&fd, &src.path().join("l"), "l", 5, &Want::Bytes(b"12345")).is_err());
        // A directory.
        std::fs::create_dir(src.path().join("d")).unwrap();
        assert!(copy_one(&fd, &src.path().join("d"), "d", 0, &Want::Bytes(b"")).is_err());
        assert_eq!(names(dst.path()), Vec::<String>::new(), "nothing was left");
    }

    #[test]
    fn a_planted_name_is_replaced_and_a_planted_symlink_is_not_followed() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let fd = open_dir(dst.path());
        std::fs::write(src.path().join("a"), b"new").unwrap();
        std::fs::write(outside.path().join("victim"), b"keep").unwrap();
        // The final name is a symlink out of the directory: `renameat` replaces the link itself.
        std::os::unix::fs::symlink(outside.path().join("victim"), dst.path().join("a")).unwrap();
        copy_one(&fd, &src.path().join("a"), "a", 3, &Want::Bytes(b"new")).unwrap();
        assert_eq!(std::fs::read(dst.path().join("a")).unwrap(), b"new");
        assert_eq!(
            std::fs::read(outside.path().join("victim")).unwrap(),
            b"keep"
        );
        assert!(
            !std::fs::symlink_metadata(dst.path().join("a"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn the_free_space_rule_is_three_copies_and_two_gib() {
        assert_eq!(needed_bytes(0), 2 * GIB);
        assert_eq!(needed_bytes(GIB), 5 * GIB);
        assert_eq!(needed_bytes(u64::MAX), u64::MAX);
    }
}
