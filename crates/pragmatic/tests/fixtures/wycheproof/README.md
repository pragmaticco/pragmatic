# Wycheproof Ed25519 vectors

`ed25519_test.json` is Project Wycheproof's EdDSA verification test file,
copied unmodified from
[C2SP/wycheproof](https://github.com/C2SP/wycheproof) at commit
`7a325932231bd7a724c791c8b0d65ea4d6d2f435`, path
`testvectors_v1/ed25519_test.json` (SHA-256
`752d2ea7d7c6cf4736381b6cbacb61f8182b126ab7cd9b058f00c50084975536`).
Wycheproof is licensed under the Apache License, Version 2.0.

The unit test `ed25519::tests::wycheproof_vectors` in `src/ed25519.rs`
parses the file with the crate's own strict JSON parser and requires every
one of the 151 cases (88 valid, 63 invalid) to get exactly the expected
result. The invalid cases include non-canonical `S` (`S >= L` and
`S + L`), malformed and truncated signatures, signatures with trailing
data, and non-canonical encodings of `R`.

To update, replace the file with a newer revision, record the commit and
hash here, and rerun `cargo test -p pragmatic`.
