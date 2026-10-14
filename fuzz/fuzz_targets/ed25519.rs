//! Ed25519 verification (RFC 8032, with the core's acceptance rules) on
//! arbitrary keys, signatures and messages: never panic, and never accept
//! a signature under a key that is not a valid point.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pragmatic::ed25519;

fuzz_target!(|data: &[u8]| {
    if data.len() < 96 {
        return;
    }
    let key: [u8; 32] = data[..32].try_into().unwrap();
    let sig: [u8; 64] = data[32..96].try_into().unwrap();
    let message = &data[96..];
    let ok = ed25519::verify(&key, message, &sig);
    if ok {
        assert!(ed25519::is_valid_public_key(&key));
    }
});
