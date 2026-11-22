//! The minisign signature file and the check of a manifest against it. Input:
//! `u16 data_len | data | signature text`. The key is the one of the minisign-verify
//! documentation; the seed is its published signature of `test`.
#![no_main]

use hx_agent::privd::update::keys::UpdateKeys;
use libfuzzer_sys::fuzz_target;

const KEY: &str = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";

fuzz_target!(|data: &[u8]| {
    let Some((len, rest)) = data.split_first_chunk::<2>() else {
        return;
    };
    let n = usize::from(u16::from_le_bytes(*len)).min(rest.len());
    let (signed, sig) = rest.split_at(n);
    let Ok(sig) = std::str::from_utf8(sig) else {
        return;
    };
    let keys = UpdateKeys::from_public_keys(&[KEY]).expect("the documentation key parses");
    if keys.verify(signed, sig).is_ok() {
        // Nobody here holds the secret key: only the published signature of `test` verifies.
        assert_eq!(signed, b"test");
    }
    // The key parser itself takes text from a file.
    let _ = UpdateKeys::from_public_keys(&[sig]);
});
