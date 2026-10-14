//! The strict JSON parser (design 3.7) on arbitrary text: it must refuse
//! what is not strict JSON and never panic, and what it accepts must
//! round-trip through its canonical form.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pragmatic::json;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(doc) = json::parse(text) {
            let again = json::parse(&doc.to_string()).expect("canonical JSON parses");
            assert_eq!(again, doc);
        }
    }
    let _ = pragmatic::redact::binary::scan(data);
});
