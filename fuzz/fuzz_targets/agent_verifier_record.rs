//! The PIN and password verifier record an admin client hands to the gateway (`SetPinVerifier`,
//! `SetPasswordVerifier`), and the cost check that guards Argon2id's memory use.
#![no_main]

use hx_agent::gateway::verifier::VerifierRecord;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(r) = VerifierRecord::parse(data) else {
        return;
    };
    // The parameters were bounded before any hashing could be asked for.
    let p = r.params();
    assert!(p.memory_kib <= 1 << 20);
    let _ = r.check_cost(19 * 1024);
    let again = VerifierRecord::parse(&r.to_bytes()).expect("a record's bytes parse");
    assert!(again == r);
});
