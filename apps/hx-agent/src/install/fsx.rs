//! Small file helpers of the installer: create what is missing with the intended mode (the
//! process umask is 0077, so nothing is public by accident), write a file only when its content
//! or mode differs, and read a bounded text file.

use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::privd::state::write_atomic;

/// Creates `dir` and every missing parent with exactly `mode` (the umask is undone for the
/// directories made here), leaving existing directories alone.
pub fn ensure_dir(dir: &Path, mode: u32) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut cur = Some(dir);
    while let Some(d) = cur {
        if std::fs::symlink_metadata(d).is_ok() || d.as_os_str().is_empty() {
            break;
        }
        missing.push(d);
        cur = d.parent();
    }
    for d in missing.into_iter().rev() {
        match std::fs::create_dir(d) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Writes `bytes` to `path` with `mode` unless the file already has exactly that content and
/// mode. Returns whether it wrote.
pub fn write_if_changed(path: &Path, bytes: &[u8], mode: u32) -> io::Result<bool> {
    if let Some(dir) = path.parent() {
        ensure_dir(dir, 0o755)?;
    }
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_file()
        && meta.permissions().mode() & 0o7777 == mode
        && std::fs::read(path).is_ok_and(|cur| cur == bytes)
    {
        return Ok(false);
    }
    write_atomic(path, bytes, mode)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(true)
}

/// The file's text, `None` when it does not exist or is not UTF-8. At most 256 KiB are read.
pub fn read_text(path: &Path) -> Option<String> {
    let f = std::fs::File::open(path).ok()?;
    let mut s = String::new();
    f.take(256 * 1024).read_to_string(&mut s).ok()?;
    Some(s)
}

/// Lower-case hex SHA-256.
pub fn sha256_hex(b: &[u8]) -> String {
    crate::privd::update::verify::hex(&Sha256::digest(b))
}

/// Removes a file; a missing one is fine.
pub fn remove_file(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_is_written_once_and_with_its_mode() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a/b/c.conf");
        assert!(write_if_changed(&p, b"x", 0o644).unwrap());
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(
            !write_if_changed(&p, b"x", 0o644).unwrap(),
            "same content and mode"
        );
        assert!(write_if_changed(&p, b"y", 0o644).unwrap(), "new content");
        assert!(write_if_changed(&p, b"y", 0o600).unwrap(), "new mode");
        assert_eq!(
            std::fs::metadata(p.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
