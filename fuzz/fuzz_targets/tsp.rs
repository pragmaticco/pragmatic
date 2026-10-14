//! The RFC 3161 time-stamp response and token parsers on arbitrary DER:
//! TSAs and evidence bundles are untrusted input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pragmatic::tsp;

fuzz_target!(|data: &[u8]| {
    if let Ok(resp) = tsp::parse_response(data) {
        if let Some(token) = resp.token {
            let _ = tsp::parse_token(&token);
        }
    }
    let _ = tsp::parse_token(data);
});
