//! `hx-pwcheck`: the current-password checker of a desktop container.
//!
//! `hx-privd` runs it inside the container (through Incus exec, as root) to verify the *current*
//! password before it lets the password change (`docs/ipc.md` 6.9). The contract is
//! `hx_provision::session::PASSWORD_CHECK_HELPER`:
//!
//! * argv is exactly `hx-pwcheck <login>`;
//! * the candidate password is the whole of standard input (no newline is stripped);
//! * the answer is the **exit status only**, nothing on stdout, nothing trusted from stderr:
//!
//! | Status | Meaning |
//! |---|---|
//! | [`EXIT_MATCH`] 0 | the password matches the user's hash in `/etc/shadow` |
//! | [`EXIT_MISMATCH`] 1 | it does not match (also: longer than 511 bytes, or containing a NUL: no password set through `chpasswd` can be) |
//! | [`EXIT_USAGE`] 2 | wrong argv or an unusable login name |
//! | [`EXIT_NO_HASH`] 3 | no such user, or the account has no usable hash: locked (`!...`), `*...` or empty |
//! | [`EXIT_UNAVAILABLE`] 4 | the check could not be made: shadow unreadable, a symlink or not a regular file, a hash libxcrypt does not understand, an I/O error |
//!
//! Anything but 0 and 1 is "could not check" to the caller, which fails closed.
//!
//! What it does:
//!
//! * reads `/etc/shadow` with `O_NOFOLLOW`, as a regular file, bounded in size;
//! * computes the hash with libxcrypt's `crypt_rn` ([`crypt`], the one audited `unsafe`
//!   module), taking the scheme and salt from the stored hash itself, so yescrypt, sha512crypt
//!   and every other scheme the distribution writes work;
//! * compares in constant time ([`subtle`]);
//! * keeps the candidate, the computed hash and libxcrypt's scratch area in buffers that are
//!   zeroed on drop, and turns off core dumps and ptrace before it reads the password.

#![deny(unsafe_code)]

pub mod crypt;

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// The password matches.
pub const EXIT_MATCH: u8 = 0;
/// The password does not match.
pub const EXIT_MISMATCH: u8 = 1;
/// Wrong usage.
pub const EXIT_USAGE: u8 = 2;
/// No such user, or locked, `*` or empty hash.
pub const EXIT_NO_HASH: u8 = 3;
/// The check could not be made.
pub const EXIT_UNAVAILABLE: u8 = 4;

/// The shadow file.
pub const SHADOW_PATH: &str = "/etc/shadow";
/// Longest candidate that can be a password: libxcrypt's `CRYPT_MAX_PASSPHRASE_SIZE` is 512
/// including the terminating NUL, and it refuses (`ERANGE`) a passphrase of 512 bytes.
pub const MAX_PASSWORD: usize = 511;
/// The most of the shadow file that is read (a shadow file of this size is absurd).
pub const MAX_SHADOW: u64 = 4 * 1024 * 1024;
/// The longest login name accepted.
pub const MAX_LOGIN: usize = 256;

/// The shadow file to read: [`SHADOW_PATH`]. Only a build with the `test-shadow-path` feature
/// (the crate's own tests) lets `HX_PWCHECK_SHADOW` replace it; a release build ignores the
/// environment entirely.
pub fn shadow_path() -> PathBuf {
    #[cfg(feature = "test-shadow-path")]
    if let Some(p) = std::env::var_os("HX_PWCHECK_SHADOW") {
        return PathBuf::from(p);
    }
    PathBuf::from(SHADOW_PATH)
}

/// A failed check, with the exit status it maps to. The text is for the journal: it never
/// holds the password, a hash or a user name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Exit 1.
    Mismatch,
    /// Exit 2.
    Usage(&'static str),
    /// Exit 3.
    NoHash(&'static str),
    /// Exit 4.
    Unavailable(&'static str),
}

impl Failure {
    /// The exit status.
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Mismatch => EXIT_MISMATCH,
            Self::Usage(_) => EXIT_USAGE,
            Self::NoHash(_) => EXIT_NO_HASH,
            Self::Unavailable(_) => EXIT_UNAVAILABLE,
        }
    }

    /// A short reason.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Mismatch => "password does not match",
            Self::Usage(r) | Self::NoHash(r) | Self::Unavailable(r) => r,
        }
    }
}

/// Is `login` something `/etc/shadow` can hold as a name? (The caller has already validated it
/// as a `Username`; this only keeps it from matching a different line or field.)
pub fn valid_login(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= MAX_LOGIN
        && !login.bytes().any(|b| b == b':' || b == b'\n' || b == 0)
}

/// The password hash of `login` in `shadow` (the first entry of that name, as `getspnam`).
///
/// A locked account (`!` or `!!`, with or without a hash after it), a `*` field, an empty
/// field and a missing user are all [`Failure::NoHash`]: there is nothing to compare with, and
/// in particular a locked hash is never compared (`!$6$...` is not the hash of anything).
pub fn find_hash<'a>(shadow: &'a [u8], login: &str) -> Result<&'a [u8], Failure> {
    for line in shadow.split(|&b| b == b'\n') {
        let mut fields = line.splitn(3, |&b| b == b':');
        let (Some(name), Some(hash)) = (fields.next(), fields.next()) else {
            continue;
        };
        if name != login.as_bytes() {
            continue;
        }
        return match hash.first() {
            None => Err(Failure::NoHash("the account has an empty hash")),
            Some(b'!' | b'*') => Err(Failure::NoHash("the account is locked or has no password")),
            Some(_) => Ok(hash),
        };
    }
    Err(Failure::NoHash("no such user"))
}

/// Does `password` hash to `stored`?
///
/// `Ok(())` for a match, [`Failure::Mismatch`] for a different password. A passphrase with a
/// NUL byte or longer than [`MAX_PASSWORD`] is a mismatch, never truncated. A stored hash that
/// libxcrypt rejects is [`Failure::Unavailable`].
pub fn verify(stored: &[u8], password: &[u8]) -> Result<(), Failure> {
    if password.len() > MAX_PASSWORD || password.contains(&0) {
        return Err(Failure::Mismatch);
    }
    let computed = crypt::crypt(password, stored)
        .map_err(|_| Failure::Unavailable("libxcrypt cannot hash with this stored hash"))?;
    if bool::from(computed.as_slice().ct_eq(stored)) {
        Ok(())
    } else {
        Err(Failure::Mismatch)
    }
}

/// Reads the shadow file: opened with `O_NOFOLLOW` (a symlink is refused), a regular file, at
/// most [`MAX_SHADOW`] bytes.
pub fn read_shadow(path: &std::path::Path) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| Failure::Unavailable("cannot open the shadow file (a symlink is refused)"))?;
    let meta = file
        .metadata()
        .map_err(|_| Failure::Unavailable("cannot stat the shadow file"))?;
    if !meta.is_file() || meta.len() > MAX_SHADOW {
        return Err(Failure::Unavailable(
            "the shadow file is not a regular file of sensible size",
        ));
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(meta.len() as usize + 1));
    file.take(MAX_SHADOW + 1)
        .read_to_end(&mut buf)
        .map_err(|_| Failure::Unavailable("cannot read the shadow file"))?;
    if buf.len() as u64 > MAX_SHADOW {
        return Err(Failure::Unavailable("the shadow file is too large"));
    }
    Ok(buf)
}

/// File descriptor 0, read directly with `read(2)`: no `std::io::Stdin` and therefore none of
/// its 8 KiB buffer, which is never wiped.
#[derive(Debug, Default, Clone, Copy)]
pub struct RawStdin;

impl Read for RawStdin {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(rustix::io::read(rustix::stdio::stdin(), buf)?)
    }
}

/// Reads the candidate: at most [`MAX_PASSWORD`] bytes are kept. `None` means "more than that"
/// (the caller answers mismatch). The bytes are read straight into one zeroed buffer of
/// `MAX_PASSWORD + 1` bytes (no intermediate buffer, no regrowth) that is wiped on drop.
pub fn read_password(mut input: impl Read) -> Result<Option<Zeroizing<Vec<u8>>>, Failure> {
    let mut buf = Zeroizing::new(vec![0u8; MAX_PASSWORD + 1]);
    let mut len = 0;
    while len < buf.len() {
        match input.read(&mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                return Err(Failure::Unavailable(
                    "cannot read the password from standard input",
                ));
            }
        }
    }
    if len > MAX_PASSWORD {
        return Ok(None);
    }
    buf.truncate(len);
    Ok(Some(buf))
}

/// The whole check: validate the login, read the password and the shadow file, compare.
pub fn check(login: &str, stdin: impl Read, shadow: &std::path::Path) -> Result<(), Failure> {
    if !valid_login(login) {
        return Err(Failure::Usage("not a usable login name"));
    }
    let password = read_password(stdin)?;
    let shadow = read_shadow(shadow)?;
    let stored = find_hash(&shadow, login)?;
    match password {
        // Too long to be a password: no hash is computed, the answer is the same.
        None => Err(Failure::Mismatch),
        Some(p) => verify(stored, &p),
    }
}

/// No core dump and no ptrace attach while a password is in memory.
pub fn harden() {
    use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};
    // Best effort: a container may refuse; the check itself does not depend on it.
    let _ = set_dumpable_behavior(DumpableBehavior::NotDumpable);
    let _ = setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    );
}

/// The program: `args` are the arguments after the program name. Returns the exit status.
pub fn run(args: &[String], stdin: impl Read) -> u8 {
    let [login] = args else {
        eprintln!("hx-pwcheck: usage: hx-pwcheck <login>, the password on standard input");
        return EXIT_USAGE;
    };
    harden();
    match check(login, stdin, &shadow_path()) {
        Ok(()) => EXIT_MATCH,
        Err(f) => {
            // Said once, for the journal; the caller reads only the status.
            eprintln!("hx-pwcheck: {}", f.reason());
            f.exit_code()
        }
    }
}
