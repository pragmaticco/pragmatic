//! Frame decoding as the server receives frames from clients (design 2.4
//! and 4.6): splitting a body into frames, decoding one frame on its own,
//! and appending a batch to an empty journal must refuse bad input with an
//! error, never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pragmatic::journal::{decode_frame, frame_hash, split_frames};
use pragmatic::Journal;

fuzz_target!(|data: &[u8]| {
    if let Ok(frames) = split_frames(data) {
        for (i, frame) in frames.iter().enumerate() {
            let _ = frame_hash(frame);
            let _ = decode_frame(frame, i as u64);
        }
    }
    let mut j = Journal::new(None);
    let _ = j.append_frames(data);
});
