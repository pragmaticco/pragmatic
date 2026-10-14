//! `Journal::parse` and `Journal::audit_bytes` on arbitrary bytes, keyed
//! and unkeyed: they must return a result (a journal, a valid prefix with a
//! torn tail, or an error), never panic or hang, and a journal that parses
//! must re-encode to the bytes it was parsed from.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pragmatic::Journal;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = Journal::parse(data, None) {
        // Format 2 decoding is canonical: what parses re-encodes to the
        // bytes it came from (format 1 is read through a converter).
        if data.get(8..12) == Some(&2u32.to_le_bytes()[..]) {
            let valid = &data[..parsed.valid_len as usize];
            assert_eq!(parsed.journal.to_bytes(), valid);
        }
        let _ = parsed.journal.audit();
    }
    let _ = Journal::audit_bytes(data, None);
    let _ = Journal::parse(data, Some(b"fuzz key"));
});
