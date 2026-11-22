//! `hx-pwcheck`'s parsing of `/etc/shadow` (root, reads the file as the desktop app asks) and
//! of the candidate password on stdin. The `crypt` call itself is not fuzzed (libxcrypt).
//! Input: `u8 login_len | login | shadow file`, and the whole input as the password stream.
#![no_main]

use std::io::Cursor;

use hx_pwcheck::{MAX_PASSWORD, find_hash, read_password, valid_login};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(Some(pw)) = read_password(Cursor::new(data)) {
        assert!(pw.len() <= MAX_PASSWORD);
        assert_eq!(&pw[..], data);
    }
    let Some((&n, rest)) = data.split_first() else {
        return;
    };
    let n = usize::from(n).min(rest.len());
    let (login, shadow) = rest.split_at(n);
    let Ok(login) = std::str::from_utf8(login) else {
        return;
    };
    let _ = valid_login(login);
    if let Ok(hash) = find_hash(shadow, login) {
        // The hash is a field of the line named `login`: never a locked or empty one.
        assert!(!hash.is_empty() && hash[0] != b'!' && hash[0] != b'*');
        assert!(!hash.contains(&b':') && !hash.contains(&b'\n'));
    }
});
