//! Stage `release` (design C4): the agent's files under `/usr/lib/hx`.
//!
//! `install.sh` downloads and checks the release with `openssl`, then runs this binary from a
//! root-only bootstrap directory (`--bootstrap-dir`). **Everything is verified again here**, with
//! the keys compiled into this binary and the same code privd uses for updates:
//!
//! 1. the directory is a real directory, ours, mode 0700; its files are opened `O_NOFOLLOW`;
//! 2. the manifest's minisign signature against the embedded keys ([`UpdateKeys`]);
//! 3. the manifest's fields ([`Manifest`]), for this channel and `x86_64`, and `version` equal to
//!    this binary's own version;
//! 4. the artifact's size and SHA-256 against the signed manifest;
//! 5. the tarball is unpacked by [`extract_tar_gz`] (ustar only, `openat2` beneath the target, no
//!    symlinks) into `/usr/lib/hx/.incoming-*`, checked, renamed to `/usr/lib/hx/<version>`, and
//!    `current` is switched to it (relative link, no `previous` on a first install);
//! 6. the bootstrap directory is removed.
//!
//! Without a bootstrap directory the stage only verifies what is installed: the agent never
//! downgrades or upgrades an installed release (updates go through privd).

use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use super::Outcome;
use crate::install::ctx::Ctx;
use crate::install::error::{InstallError, Result};
use crate::install::fsx::ensure_dir;
use crate::install::paths;
use crate::privd::update::extract::{Limits, extract_tar_gz};
use crate::privd::update::manifest::{Expect, MAX_ARTIFACT_BYTES, Manifest};
use crate::privd::update::switch::Layout;
use crate::privd::update::verify::{digest_eq, hex};

/// This binary's version: the version the installed release must have.
pub const OWN_VERSION: &str = env!("CARGO_PKG_VERSION");
/// File names inside the bootstrap directory (C4).
pub const MANIFEST: &str = "manifest.json";
/// The manifest's signature.
pub const MANIFEST_SIG: &str = "manifest.json.minisig";
/// The artifact.
pub const ARTIFACT: &str = "artifact.tar.gz";

fn layout(ctx: &Ctx<'_>) -> Layout {
    Layout::new(ctx.paths.at(paths::USR_LIB_HX))
}

/// The version `current` points at, if it is a complete release.
pub fn installed_current(ctx: &Ctx<'_>) -> Option<String> {
    let l = layout(ctx);
    let v = l.current().ok().flatten()?;
    l.verify_dir(&v).ok().map(|()| v)
}

/// Done-check: `current` resolves to a complete release of this version.
pub fn check(ctx: &mut Ctx<'_>) -> Result<bool> {
    Ok(installed_current(ctx).as_deref() == Some(OWN_VERSION))
}

fn open_nofollow(dir: &Path, name: &str, max: u64) -> Result<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32)
        .open(dir.join(name))
        .map_err(|e| {
            InstallError::verify(format!(
                "cannot open {name} in the bootstrap directory: {}",
                e.kind()
            ))
        })?;
    let m = f.metadata()?;
    if !m.is_file() {
        return Err(InstallError::verify(format!(
            "{name} is not a regular file"
        )));
    }
    if m.len() > max {
        return Err(InstallError::verify(format!(
            "{name} is larger than allowed"
        )));
    }
    Ok(f)
}

fn read_small(dir: &Path, name: &str, max: u64) -> Result<Vec<u8>> {
    let mut f = open_nofollow(dir, name, max)?;
    let mut v = Vec::new();
    f.by_ref().take(max).read_to_end(&mut v)?;
    Ok(v)
}

/// Checks the bootstrap directory itself: not a link, a directory, ours, mode 0700.
pub(crate) fn check_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(dir)
        .map_err(|_| InstallError::verify("the bootstrap directory does not exist"))?;
    if !m.file_type().is_dir() {
        return Err(InstallError::verify(
            "the bootstrap directory is not a directory (a symlink is refused)",
        ));
    }
    if m.uid() != rustix::process::geteuid().as_raw() || m.mode() & 0o077 != 0 {
        return Err(InstallError::verify(
            "the bootstrap directory is not owned by root with mode 0700",
        ));
    }
    Ok(())
}

/// Verifies the bootstrap directory and installs the release it holds.
fn install_bootstrap(ctx: &mut Ctx<'_>, dir: &Path) -> Result<()> {
    check_dir(dir)?;
    let manifest_bytes = read_small(dir, MANIFEST, 1024 * 1024)?;
    let sig = read_small(dir, MANIFEST_SIG, 8192)?;
    let sig_text = String::from_utf8(sig)
        .map_err(|_| InstallError::verify("the signature file is not text"))?;
    ctx.keys
        .verify(&manifest_bytes, &sig_text)
        .map_err(|e| InstallError::verify(format!("the manifest signature is not valid: {e}")))?;
    let release = Manifest::parse(&manifest_bytes)
        .and_then(|m| {
            m.check(&Expect {
                channel: &ctx.opts.channel,
                arch: "x86_64",
                now: (ctx.now)(),
            })
        })
        .map_err(|e| InstallError::verify(format!("the manifest is not acceptable: {e}")))?;
    let m = &release.manifest;
    if m.version != OWN_VERSION {
        return Err(InstallError::verify(format!(
            "the release is version {} but this hx-agent is {OWN_VERSION}",
            crate::cli::text::peer(&m.version, 32)
        )));
    }
    let mut artifact = open_nofollow(dir, ARTIFACT, MAX_ARTIFACT_BYTES)?;
    if artifact.metadata()?.len() != m.size {
        return Err(InstallError::verify(
            "the artifact's size is not the signed size",
        ));
    }
    // Hash the artifact in one pass, then rewind for extraction (the directory is root-only, so
    // nobody can swap the file in between).
    {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = artifact.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        if !digest_eq(&hex(&h.finalize()), &m.sha256) {
            return Err(InstallError::verify(
                "the artifact's SHA-256 is not the signed one",
            ));
        }
    }
    artifact.seek(SeekFrom::Start(0))?;

    let versions_dir = ctx.paths.at(paths::USR_LIB_HX);
    ensure_dir(&versions_dir, 0o755)?;
    let l = Layout::new(&versions_dir);
    let version = m.version.clone();
    let (incoming, fd) = l
        .begin(&version)
        .map_err(|e| InstallError::tool(format!("cannot prepare /usr/lib/hx: {e}")))?;
    let extracted = extract_tar_gz(&artifact, fd.as_fd(), &Limits::default(), &|| false);
    drop(fd);
    if let Err(e) = extracted {
        l.discard(&incoming);
        return Err(InstallError::verify(format!(
            "the release cannot be unpacked: {e}"
        )));
    }
    if let Err(m) = l.verify_incoming(&incoming, &version) {
        l.discard(&incoming);
        return Err(InstallError::verify(format!(
            "the release is incomplete: {m}"
        )));
    }
    l.publish(&incoming, &version)
        .and_then(|()| l.switch_to(&version).map(|_| ()))
        .map_err(|e| InstallError::tool(format!("cannot switch to the new release: {e}")))?;
    Ok(())
}

/// Installs the release from the bootstrap directory, or verifies the installed one.
pub fn run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    let installed = installed_current(ctx);
    match (&ctx.bootstrap_dir.clone(), installed.as_deref()) {
        (_, Some(v)) if v == OWN_VERSION => {}
        (Some(dir), _) => install_bootstrap(ctx, dir)?,
        (None, Some(v)) => {
            return Err(InstallError::verify(format!(
                "the installed release is {v}, not {OWN_VERSION}; updates go through hx-agent update"
            )));
        }
        (None, None) => {
            return Err(InstallError::verify(
                "no release is installed and no bootstrap directory was given (run through install.sh)",
            ));
        }
    }
    // The bootstrap directory has done its job (also when the release was already installed).
    if let Some(dir) = ctx.bootstrap_dir.clone()
        && dir.starts_with(ctx.paths.at("/run"))
        && check_dir(&dir).is_ok()
    {
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(Outcome::Done)
}
