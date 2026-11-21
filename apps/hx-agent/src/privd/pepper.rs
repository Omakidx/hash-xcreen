//! The pepper of the PIN and password verifiers (ipc.md 5.3).
//!
//! A verifier is `HMAC-SHA256(HKDF(pepper, purpose), Argon2id(secret))`. The Argon2id step runs in
//! gatewayd; this module is the second step, which only privd can run. The pepper is 32 random
//! bytes generated at the first start and kept in a root-only file; it is never sent over the
//! socket, logged or put in an error. The key for each purpose is derived with HKDF-SHA256 and
//! zeroized after use.

use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use super::limiter::Purpose;

/// Length of the pepper and of every MAC.
pub const LEN: usize = 32;
/// Version of the scheme, returned by `PepperEnrol` next to the MAC.
pub const VERSION: u8 = 1;

/// The loaded pepper. `Debug` shows nothing; the bytes are zeroized on drop.
pub struct Pepper(Zeroizing<[u8; LEN]>);

impl std::fmt::Debug for Pepper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pepper(<redacted>)")
    }
}

/// Reads exactly 32 bytes from a regular file that is owned by this process's effective uid and
/// not accessible to group or others. The owner and mode are checked on the open descriptor.
fn read_key_file(path: &Path) -> io::Result<Zeroizing<[u8; LEN]>> {
    let f = std::fs::File::open(path)?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the pepper is not a regular file",
        ));
    }
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the pepper file has the wrong owner",
        ));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the pepper file is readable by group or others",
        ));
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(LEN + 1));
    f.take(LEN as u64 + 1).read_to_end(&mut buf)?;
    if buf.len() != LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the pepper file has the wrong length",
        ));
    }
    let mut key = Zeroizing::new([0u8; LEN]);
    key.copy_from_slice(&buf);
    Ok(key)
}

/// Name of the credential that carries the pepper (`LoadCredentialEncrypted=pepper:...`).
pub const CREDENTIAL_NAME: &str = "pepper";

impl Pepper {
    /// The pepper, from the systemd credential when there is one, else from the state file.
    ///
    /// With `LoadCredentialEncrypted=pepper:/etc/hx/creds/pepper.cred` systemd decrypts the pepper
    /// (sealed to the TPM where there is one) into the unit's credential directory, and that
    /// is the source. Without it (a development run, or a host still migrating) the root-only
    /// state file `pepper.key` is used, created on first use. A credential that is present but
    /// wrong (length, owner, mode) is an error, never a silent fallback.
    pub fn load(credentials_dir: Option<&Path>, state_file: &Path) -> io::Result<Self> {
        if let Some(dir) = credentials_dir {
            let cred = dir.join(CREDENTIAL_NAME);
            match std::fs::symlink_metadata(&cred) {
                Ok(_) => return Ok(Self(read_key_file(&cred)?)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Self::load_or_create(state_file)
    }

    /// Loads the pepper from `path`, creating it (mode 0600, 32 bytes from the OS random source)
    /// if it does not exist.
    ///
    /// Creation is atomic: the key is written and synced to a temporary file that is then hard
    /// linked to `path` (which fails if `path` exists), so `path` never exists half written and a
    /// second process cannot replace a key another one created. A file of the wrong length, owner
    /// or mode is an error: privd refuses to run with a pepper it cannot vouch for.
    pub fn load_or_create(path: &Path) -> io::Result<Self> {
        match read_key_file(path) {
            Ok(k) => return Ok(Self(k)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let dir = path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent directory"))?;
        let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
        tmp_name.push(format!(".tmp{}", std::process::id()));
        let tmp = dir.join(tmp_name);
        let _ = std::fs::remove_file(&tmp);
        let mut key = Zeroizing::new([0u8; LEN]);
        getrandom::fill(&mut key[..]).map_err(io::Error::other)?;
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&key[..])?;
            f.sync_all()?;
        }
        let linked = std::fs::hard_link(&tmp, path);
        let _ = std::fs::remove_file(&tmp);
        match linked {
            Ok(()) => {
                std::fs::File::open(dir)?.sync_all()?;
                Ok(Self(key))
            }
            // Someone created it first: theirs is the pepper.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(Self(read_key_file(path)?)),
            Err(e) => Err(e),
        }
    }

    /// A pepper with fixed bytes (tests).
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_bytes(bytes: [u8; LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn purpose_key(&self, purpose: Purpose) -> Zeroizing<[u8; LEN]> {
        let hk = Hkdf::<Sha256>::new(None, &self.0[..]);
        let mut info = b"hx-privd-pepper/v1/".to_vec();
        info.extend_from_slice(purpose.label().as_bytes());
        let mut out = Zeroizing::new([0u8; LEN]);
        // 32 bytes is far below the HKDF-SHA256 output limit; expand cannot fail.
        let _ = hk.expand(&info, &mut out[..]);
        out
    }

    /// `HMAC-SHA256(HKDF(pepper, purpose), input)`.
    ///
    /// Only `PepperEnrol` hands this value to a caller. `verify` never does.
    pub fn mac(&self, purpose: Purpose, input: &[u8]) -> [u8; LEN] {
        let key = self.purpose_key(purpose);
        // HMAC accepts keys of any length; new_from_slice cannot fail.
        let mut m = Hmac::<Sha256>::new_from_slice(&key[..]).expect("HMAC takes any key length");
        m.update(input);
        let mut out = [0u8; LEN];
        out.copy_from_slice(&m.finalize().into_bytes());
        out
    }

    /// Whether `expected` equals the MAC of `input`, in constant time. Returns only the verdict.
    pub fn verify(&self, purpose: Purpose, input: &[u8], expected: &[u8]) -> bool {
        let mut mac = self.mac(purpose, input);
        let ok = expected.len() == LEN && bool::from(mac.ct_eq(expected));
        mac.zeroize();
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_is_deterministic_and_separated_by_purpose_and_pepper() {
        let p = Pepper::from_bytes([7; LEN]);
        let q = Pepper::from_bytes([8; LEN]);
        let input = [1u8; 32];
        let a = p.mac(Purpose::Pin, &input);
        assert_eq!(a, p.mac(Purpose::Pin, &input));
        assert_ne!(a, p.mac(Purpose::Password, &input));
        assert_ne!(a, q.mac(Purpose::Pin, &input));
        assert_ne!(a, p.mac(Purpose::Pin, &[2u8; 32]));
    }

    #[test]
    fn verify_accepts_only_the_exact_mac() {
        let p = Pepper::from_bytes([7; LEN]);
        let input = [1u8; 32];
        let mac = p.mac(Purpose::Pin, &input);
        assert!(p.verify(Purpose::Pin, &input, &mac));
        assert!(!p.verify(Purpose::Password, &input, &mac));
        let mut bad = mac;
        bad[31] ^= 1;
        assert!(!p.verify(Purpose::Pin, &input, &bad));
        assert!(!p.verify(Purpose::Pin, &input, &mac[..31]));
    }

    #[test]
    fn the_file_is_created_0600_reloaded_and_checked() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("pepper.key");
        let p = Pepper::load_or_create(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let q = Pepper::load_or_create(&path).unwrap();
        assert_eq!(p.mac(Purpose::Pin, &[0; 32]), q.mac(Purpose::Pin, &[0; 32]));
        // Wrong length and wrong mode are refused.
        std::fs::write(&path, b"short").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Pepper::load_or_create(&path).is_err());
        std::fs::write(&path, [0u8; LEN]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Pepper::load_or_create(&path).is_err());
    }

    #[test]
    fn n6_creation_is_atomic_and_leaves_no_temporary_file() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("pepper.key");
        let a = Pepper::load_or_create(&path).unwrap();
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["pepper.key"]);
        // A second creator finds the first one's key and does not replace it.
        let b = Pepper::load_or_create(&path).unwrap();
        assert_eq!(a.mac(Purpose::Pin, &[0; 32]), b.mac(Purpose::Pin, &[0; 32]));
        // A symlink is not followed to a key elsewhere? It is a regular-file check on the target:
        // the pepper must be a regular file with our owner and mode.
        let dir2 = d.path().join("sub");
        std::fs::create_dir(&dir2).unwrap();
        std::os::unix::fs::symlink("/dev/null", dir2.join("pepper.key")).unwrap();
        assert!(Pepper::load_or_create(&dir2.join("pepper.key")).is_err());
    }

    #[test]
    fn n7_the_systemd_credential_wins_and_a_bad_one_is_an_error_not_a_fallback() {
        let d = tempfile::tempdir().unwrap();
        let creds = d.path().join("creds");
        std::fs::create_dir(&creds).unwrap();
        let state = d.path().join("pepper.key");
        let from_state = Pepper::load(Some(&creds), &state).unwrap(); // no credential: state file
        std::fs::write(creds.join(CREDENTIAL_NAME), [9u8; LEN]).unwrap();
        std::fs::set_permissions(
            creds.join(CREDENTIAL_NAME),
            std::fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        let from_cred = Pepper::load(Some(&creds), &state).unwrap();
        assert_eq!(
            from_cred.mac(Purpose::Pin, &[1; 32]),
            Pepper::from_bytes([9; LEN]).mac(Purpose::Pin, &[1; 32])
        );
        assert_ne!(
            from_cred.mac(Purpose::Pin, &[1; 32]),
            from_state.mac(Purpose::Pin, &[1; 32])
        );
        // Wrong length and wrong mode: refused, and the state file is not used instead.
        std::fs::set_permissions(
            creds.join(CREDENTIAL_NAME),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::write(creds.join(CREDENTIAL_NAME), b"short").unwrap();
        assert!(Pepper::load(Some(&creds), &state).is_err());
        std::fs::write(creds.join(CREDENTIAL_NAME), [9u8; LEN]).unwrap();
        std::fs::set_permissions(
            creds.join(CREDENTIAL_NAME),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(Pepper::load(Some(&creds), &state).is_err());
    }

    #[test]
    fn debug_never_shows_bytes() {
        let p = Pepper::from_bytes([0x41; LEN]);
        let s = format!("{p:?}");
        assert!(!s.contains("41") && !s.contains("65"));
    }
}
