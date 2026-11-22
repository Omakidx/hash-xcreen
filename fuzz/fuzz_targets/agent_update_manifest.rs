//! The update manifest (signed, but parsed before the signature of a later release is trusted
//! to be fresh, and by a root daemon): JSON parse, then every field check.
#![no_main]

use hx_agent::privd::update::manifest::{Expect, MAX_ARTIFACT_BYTES, Manifest, artifact_name};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(m) = Manifest::parse(data) else {
        return;
    };
    let expect = Expect {
        channel: "stable",
        arch: "x86_64",
        now: 1_800_000_000,
    };
    if let Ok(r) = m.check(&expect) {
        let m = &r.manifest;
        assert_eq!(m.artifact, artifact_name(&m.version, &m.arch));
        assert!(m.size >= 1 && m.size <= MAX_ARTIFACT_BYTES);
        assert_eq!(m.sha256.len(), 64);
        assert!(
            m.sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        // The artifact name is a file name the fetcher will create: no separators.
        assert!(!m.artifact.contains('/') && !m.artifact.contains('\0'));
    }
});
