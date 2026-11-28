//! The credentials a job needs from the host (ipc.md section 34 and section 26, "Admission").
//!
//! * [`read_backup_key`]: the host's backup key, slot 0 of the jobs on a server that made the
//!   repository. Read at admission from `$CREDENTIALS_DIRECTORY/backup-key`, into a `Zeroizing`
//!   buffer, never cached, never logged.
//! * [`drive_token_present`]: whether `/etc/hx/creds/drive-token.cred` exists. privd never reads
//!   the token (only the Drive helper loads it); a missing file means `DRIVE_RECONNECT`.

use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use hx_ipc::repo::{MAX_SECRET_BYTES, MIN_SECRET_BYTES};
use rustix::fs::OFlags;
use zeroize::Zeroizing;

/// Why the backup key cannot be used. The text never carries content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredError {
    /// There is no credential (no credentials directory, or no such file).
    #[error("the backup key credential is not there")]
    Missing,
    /// The file is not what section 34 requires.
    #[error("the backup key credential is not usable: {0}")]
    Malformed(&'static str),
}

/// Reads the backup key from `dir/backup-key`: a regular file (a link is refused), owned by
/// `expected_owner` when given (root in production) with no group or other permission, 16 to
/// 1 024 bytes after one trailing newline is removed, no NUL.
pub fn read_backup_key(
    dir: Option<&Path>,
    expected_owner: Option<u32>,
) -> Result<Zeroizing<Vec<u8>>, CredError> {
    let dir = dir.ok_or(CredError::Missing)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32 | OFlags::CLOEXEC.bits() as i32)
        .open(dir.join("backup-key"))
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => CredError::Missing,
            _ => CredError::Malformed("it cannot be opened (a link is refused)"),
        })?;
    let meta = file
        .metadata()
        .map_err(|_| CredError::Malformed("it cannot be read"))?;
    if !meta.is_file() {
        return Err(CredError::Malformed("it is not a regular file"));
    }
    if expected_owner.is_some_and(|uid| meta.uid() != uid) {
        return Err(CredError::Malformed("it has the wrong owner"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(CredError::Malformed("it is readable by group or other"));
    }
    if meta.len() > (MAX_SECRET_BYTES + 1) as u64 {
        return Err(CredError::Malformed("it is too long"));
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(meta.len() as usize + 1));
    file.take(MAX_SECRET_BYTES as u64 + 2)
        .read_to_end(&mut buf)
        .map_err(|_| CredError::Malformed("it cannot be read"))?;
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&buf.len()) {
        return Err(CredError::Malformed(
            "its length is outside 16 to 1 024 bytes",
        ));
    }
    if buf.contains(&0) {
        return Err(CredError::Malformed("it contains a NUL byte"));
    }
    Ok(buf)
}

/// Whether the sealed Drive token credential exists as a regular file. Its content is never read.
pub fn drive_token_present(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn dir_with(content: &[u8], mode: u32) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("backup-key");
        std::fs::write(&p, content).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        d
    }

    fn me() -> u32 {
        rustix::process::getuid().as_raw()
    }

    #[test]
    fn a_good_key_is_read_without_its_newline() {
        let d = dir_with(b"0123456789abcdef-fake-key-value\n", 0o400);
        let k = read_backup_key(Some(d.path()), Some(me())).unwrap();
        assert_eq!(&k[..], b"0123456789abcdef-fake-key-value");
        // 0600 is fine too, and the owner check is skipped with None.
        let d = dir_with(&[b'k'; 1024], 0o600);
        assert_eq!(read_backup_key(Some(d.path()), None).unwrap().len(), 1024);
    }

    #[test]
    fn every_malformed_credential_is_refused_with_a_text_that_has_no_content() {
        let secret = "SUPERSECRETVALUE-0123456789";
        for (content, mode, owner) in [
            (&b"short"[..], 0o400, Some(me())),
            (&[b'k'; 1025][..], 0o400, Some(me())),
            (&b"0123456789abcdef\0xxxx"[..], 0o400, Some(me())),
            (secret.as_bytes(), 0o440, Some(me())),
            (secret.as_bytes(), 0o404, Some(me())),
            (secret.as_bytes(), 0o400, Some(me().wrapping_add(1))),
        ] {
            let d = dir_with(content, mode);
            let e = read_backup_key(Some(d.path()), owner).unwrap_err();
            let text = format!("{e} {e:?}");
            assert!(matches!(e, CredError::Malformed(_)), "{text}");
            assert!(!text.contains("SUPERSECRET"), "{text}");
        }
    }

    #[test]
    fn missing_and_linked_credentials_are_refused() {
        assert_eq!(read_backup_key(None, None).unwrap_err(), CredError::Missing);
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            read_backup_key(Some(d.path()), None).unwrap_err(),
            CredError::Missing
        );
        let target = d.path().join("elsewhere");
        std::fs::write(&target, b"0123456789abcdef0123").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::os::unix::fs::symlink(&target, d.path().join("backup-key")).unwrap();
        assert!(matches!(
            read_backup_key(Some(d.path()), None),
            Err(CredError::Malformed(_))
        ));
    }

    #[test]
    fn the_drive_token_is_checked_by_existence_only() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("drive-token.cred");
        assert!(!drive_token_present(&p));
        std::fs::write(&p, b"sealed").unwrap();
        assert!(drive_token_present(&p));
        let l = d.path().join("link.cred");
        std::os::unix::fs::symlink(&p, &l).unwrap();
        assert!(!drive_token_present(&l), "a link is not the credential");
        assert!(!drive_token_present(d.path()));
    }
}
