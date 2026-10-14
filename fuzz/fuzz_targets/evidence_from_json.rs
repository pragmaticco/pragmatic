//! Evidence bundles are untrusted input (design 5.3): parsing one must
//! refuse what is malformed and never panic, and verifying whatever parses,
//! without OpenSSL, must report rather than panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pragmatic::evidence::{self, Bundle, NoTsaVerifier, TrustPolicy};

fuzz_target!(|data: &[u8]| {
    if let Ok(bundle) = Bundle::from_json(data) {
        let _ = evidence::verify(&bundle, &TrustPolicy::default(), &NoTsaVerifier);
    }
});
