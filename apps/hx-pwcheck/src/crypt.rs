//! The one audited `unsafe` module of `hx-pwcheck`: libxcrypt's `crypt_rn`.
//!
//! libxcrypt (Debian and Ubuntu package `libcrypt1`, which is Essential) implements every
//! `crypt(3)` scheme the distributions write to `/etc/shadow`: yescrypt (`$y$`), sha512crypt
//! (`$6$`), sha256crypt, bcrypt and the legacy ones. `crypt_rn` is the re-entrant, caller-buffer
//! variant: it neither uses nor leaves a static buffer, and it returns `NULL` on failure instead
//! of a failure token.
//!
//! Rules this module keeps:
//!
//! * The library is linked **dynamically** by its soname (`libcrypt.so.1`, a verbatim `-l`), so
//!   the build needs only the runtime package, not `libcrypt-dev`, and the binary picks up the
//!   distribution's security updates.
//! * The passphrase is passed as a NUL-terminated copy held in a [`Zeroizing`] buffer. A
//!   passphrase that contains a NUL is refused *before* the call: C would stop at it and the
//!   check would compare only a prefix.
//! * The scratch area libxcrypt works in (`struct crypt_data`, 32 KiB, holds a copy of the
//!   passphrase and key-derivation state) is a heap buffer that is zeroed on drop.
//! * The output is copied out once into a [`Zeroizing`] buffer and never trusted: the caller
//!   compares it with the stored hash in constant time.

#![allow(unsafe_code)]

use std::ffi::{CStr, c_char, c_int, c_void};

use zeroize::{Zeroize, Zeroizing};

#[link(name = "libcrypt.so.1", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    /// `char *crypt_rn(const char *phrase, const char *setting, struct crypt_data *data, int
    /// size)`. `data` must be zero-filled before the first call and `size` at least
    /// `sizeof(struct crypt_data)`; returns a pointer into `data` or `NULL`.
    fn crypt_rn(
        phrase: *const c_char,
        setting: *const c_char,
        data: *mut c_void,
        size: c_int,
    ) -> *mut c_char;
}

/// `sizeof(struct crypt_data)` in libxcrypt 4.x is 32768 bytes (output 384, setting 384, input
/// 512, reserved 767, a flag byte, 30720 of internal state). The library refuses a smaller
/// buffer (`ERANGE`); the buffer here is twice that, which it accepts.
const DATA_SIZE: usize = 65536;

/// The scratch area, zero-filled, aligned, wiped on drop.
#[repr(C, align(64))]
struct CryptData([u8; DATA_SIZE]);

impl Drop for CryptData {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Why a hash could not be computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptError {
    /// The passphrase or the setting contains a NUL byte.
    Nul,
    /// libxcrypt returned `NULL` or a failure token: an unsupported or malformed setting, a
    /// passphrase it refuses (too long), or no memory.
    Failed,
}

/// Computes `crypt(phrase, setting)`. `setting` is a salt, or a complete stored hash (the
/// scheme, its parameters and the salt are read from its prefix and the rest is ignored).
pub fn crypt(phrase: &[u8], setting: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptError> {
    if phrase.contains(&0) || setting.contains(&0) {
        return Err(CryptError::Nul);
    }
    let mut phrase_c = Zeroizing::new(Vec::with_capacity(phrase.len() + 1));
    phrase_c.extend_from_slice(phrase);
    phrase_c.push(0);
    let mut setting_c = Vec::with_capacity(setting.len() + 1);
    setting_c.extend_from_slice(setting);
    setting_c.push(0);

    let mut data = Box::new(CryptData([0u8; DATA_SIZE]));
    // SAFETY: `phrase_c` and `setting_c` are NUL-terminated, contain no other NUL and outlive
    // the call. `data` is a zero-filled, 64-byte-aligned, exclusively owned buffer of
    // `DATA_SIZE` bytes, and `size` is exactly that, at least `sizeof(struct crypt_data)`. The
    // function reads the two strings, writes only inside `data` and returns either NULL or a
    // pointer to a NUL-terminated string inside `data`.
    let out = unsafe {
        crypt_rn(
            phrase_c.as_ptr().cast(),
            setting_c.as_ptr().cast(),
            std::ptr::from_mut(&mut *data).cast(),
            DATA_SIZE as c_int,
        )
    };
    if out.is_null() {
        return Err(CryptError::Failed);
    }
    // SAFETY: `out` is non-null and, per the contract above, points to a NUL-terminated string
    // inside `data`, which is alive and not modified until the copy is made.
    let bytes = unsafe { CStr::from_ptr(out) }.to_bytes();
    // Old interfaces signal failure with a token that starts with `*` (`*0`, `*1`).
    if bytes.is_empty() || bytes[0] == b'*' {
        return Err(CryptError::Failed);
    }
    Ok(Zeroizing::new(bytes.to_vec()))
}
