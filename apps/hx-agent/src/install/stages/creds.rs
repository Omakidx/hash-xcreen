//! Stage `credentials` (design C7): `pepper.cred` and `identity.cred`, sealed with
//! `systemd-creds` (to the TPM where there is one, else to the host key).
//!
//! * Both are 32 random bytes from `getrandom`, written to `systemd-creds encrypt --name=<n> - <tmp>`
//!   **through the tool's standard input** (never an argument), then renamed to 0600. The
//!   plaintext lives only in `Zeroizing` memory.
//! * The identity key's public half is derived when the seed is made and kept in the state as
//!   `server_public_key`, so an SSH app can cross-check the key it pins while pairing.
//! * **Migrating `pepper.key`** (an older install that kept the pepper in a plain file): the MAC of
//!   a fixed test input is taken before and after the pepper is sealed and privd is restarted; only
//!   when both are equal is the plain file wiped (zeros, fsync) and removed. If they differ the new
//!   `.cred` is removed, the key stays, and the stage fails.
//! * Done when both `.cred` files exist (0600), decrypt to 32 bytes, and no `pepper.key` is left.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use hx_ipc::privd::pb::LockoutPurpose;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::Outcome;
use crate::install::ctx::Ctx;
use crate::install::error::{InstallError, Result};
use crate::install::fsx::{ensure_dir, remove_file};
use crate::install::paths;
use crate::install::runner::{Call, Tool};
use crate::privd::pepper::LEN;

/// The fixed input whose MAC proves that the sealed pepper is the old one (not a secret).
const CHECK_INPUT: [u8; 32] = [0x5a; 32];

fn cred_abs(name: &str) -> String {
    format!("{}/{name}.cred", paths::CREDS_DIR)
}

/// Seals `plain` as the credential `name`.
fn seal(ctx: &mut Ctx<'_>, name: &str, plain: &[u8]) -> Result<()> {
    let fin = ctx.paths.at(&cred_abs(name));
    let tmp = ctx.paths.at(&format!("{}.tmp", cred_abs(name)));
    remove_file(&tmp)?;
    ensure_dir(&ctx.paths.at(paths::CREDS_DIR), 0o700)?;
    let call = Call::owned(
        Tool::SystemdCreds,
        vec![
            "encrypt".into(),
            format!("--name={name}"),
            "-".into(),
            tmp.to_string_lossy().into_owned(),
        ],
    )
    .with_stdin(Zeroizing::new(plain.to_vec()));
    if let Err(e) = ctx.run_ok(call) {
        let _ = remove_file(&tmp);
        return Err(e);
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(&tmp, &fin)?;
    ctx.state.created_file(&cred_abs(name));
    Ok(())
}

/// Decrypts the credential `name`. The result is wiped on drop.
fn unseal(ctx: &mut Ctx<'_>, name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let path = ctx.paths.arg(&cred_abs(name));
    let out = ctx.run_ok(Call::owned(
        Tool::SystemdCreds,
        vec!["decrypt".into(), format!("--name={name}"), path, "-".into()],
    ))?;
    Ok(Zeroizing::new(out.stdout.to_vec()))
}

fn is_private_file(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .is_ok_and(|m| m.file_type().is_file() && m.permissions().mode() & 0o077 == 0)
}

fn random32() -> Result<Zeroizing<[u8; LEN]>> {
    let mut b = Zeroizing::new([0u8; LEN]);
    rustix::rand::getrandom(&mut *b, rustix::rand::GetRandomFlags::empty())
        .map_err(|e| InstallError::internal(format!("no randomness: {e}")))?;
    Ok(b)
}

/// Overwrites a file with zeros, syncs and removes it.
pub fn wipe_file(p: &Path) -> std::io::Result<()> {
    let len = std::fs::metadata(p)?.len();
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(p)?;
        let zeros = vec![0u8; usize::try_from(len).unwrap_or(0)];
        f.write_all(&zeros)?;
        f.sync_all()?;
    }
    std::fs::remove_file(p)
}

/// Done-check.
pub fn check(ctx: &mut Ctx<'_>) -> Result<bool> {
    if ctx.paths.at(paths::PEPPER_KEY).exists() {
        return Ok(false);
    }
    for n in ["pepper", "identity"] {
        if !is_private_file(&ctx.paths.at(&cred_abs(n))) {
            return Ok(false);
        }
        match unseal(ctx, n) {
            Ok(v) if v.len() == LEN => {}
            _ => return Ok(false),
        }
    }
    Ok(!ctx.state.server_public_key.is_empty())
}

fn restart_privd_and_wait(ctx: &mut Ctx<'_>) -> Result<()> {
    ctx.run_ok(Call::new(Tool::Systemctl, &["restart", "hx-privd.service"]).timeout_secs(120))?;
    let mut last = InstallError::unavailable("hx-privd did not answer");
    for _ in 0..60 {
        match ctx.daemons.hello() {
            Ok(_) => return Ok(()),
            Err(e) => last = e,
        }
        ctx.probe.sleep(std::time::Duration::from_millis(500));
    }
    Err(last)
}

fn migrate_pepper(ctx: &mut Ctx<'_>, key_path: &Path) -> Result<()> {
    let key = {
        let b = std::fs::read(key_path)?;
        Zeroizing::new(b)
    };
    if key.len() != LEN {
        return Err(InstallError::internal(
            "the old pepper.key is not 32 bytes; refusing to migrate it",
        ));
    }
    let mac1 = ctx
        .daemons
        .pepper_enrol(LockoutPurpose::Pin, &CHECK_INPUT)?;
    seal(ctx, "pepper", &key)?;
    let after = restart_privd_and_wait(ctx)
        .and_then(|()| ctx.daemons.pepper_enrol(LockoutPurpose::Pin, &CHECK_INPUT));
    let same = after
        .as_ref()
        .is_ok_and(|m2| m2.len() == mac1.len() && bool::from(m2.ct_eq(&mac1)));
    if !same {
        let _ = remove_file(&ctx.paths.at(&cred_abs("pepper")));
        return Err(InstallError::tool(
            "the sealed pepper does not give the same MACs as pepper.key; the key was kept and the sealed copy removed",
        ));
    }
    wipe_file(key_path)?;
    Ok(())
}

/// Seals the pepper and the identity key.
pub fn run(ctx: &mut Ctx<'_>) -> Result<Outcome> {
    let key_path = ctx.paths.at(paths::PEPPER_KEY);
    let pepper_cred = ctx.paths.at(&cred_abs("pepper"));
    match (key_path.exists(), pepper_cred.exists()) {
        (true, false) => migrate_pepper(ctx, &key_path)?,
        (true, true) => {
            let plain = unseal(ctx, "pepper")?;
            let key = Zeroizing::new(std::fs::read(&key_path)?);
            if plain.len() == key.len() && bool::from(plain.ct_eq(&key)) {
                wipe_file(&key_path)?;
            } else {
                let stamp = (ctx.now)();
                let orphan = key_path.with_file_name(format!("pepper.key.orphaned-{stamp}"));
                std::fs::rename(&key_path, &orphan)?;
                ctx.warn(
                    "credentials",
                    "pepper.key differs from the sealed pepper; it was renamed to pepper.key.orphaned-<time> and kept",
                );
            }
        }
        (false, false) => {
            let p = random32()?;
            seal(ctx, "pepper", &*p)?;
        }
        (false, true) => {}
    }
    let identity_cred = ctx.paths.at(&cred_abs("identity"));
    let seed = if identity_cred.exists() {
        unseal(ctx, "identity")?
    } else {
        let key = hx_crypto::IdentityKey::generate().map_err(|e| {
            InstallError::internal(format!("cannot generate the identity key: {e}"))
        })?;
        let seed = Zeroizing::new(key.seed().to_vec());
        seal(ctx, "identity", &seed)?;
        seed
    };
    let mut arr = Zeroizing::new([0u8; 32]);
    if seed.len() != 32 {
        return Err(InstallError::internal(
            "the sealed identity key is not 32 bytes",
        ));
    }
    arr.copy_from_slice(&seed);
    let key = hx_crypto::IdentityKey::from_seed(&arr)
        .map_err(|_| InstallError::internal("the sealed identity key is not valid"))?;
    ctx.state.server_public_key = crate::cli::text::hex(key.public().as_bytes());
    Ok(Outcome::Done)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wiping_zeroes_then_removes() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("k");
        std::fs::write(&p, [7u8; 32]).unwrap();
        wipe_file(&p).unwrap();
        assert!(!p.exists());
    }
}
