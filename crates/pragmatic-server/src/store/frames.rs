//! Reading a journal's entries from disk by offset, and bounding what any
//! reader holds whole.
//!
//! A page of entries, one slot, or the hashes a resend is compared against
//! never needs the whole journal: a journal is a header followed by frames
//! (`len u32 ‖ record ‖ hash`), so walking the length prefixes once gives
//! where each entry starts, and a frame read at its offset decodes on its
//! own ([`decode_frame`]). The offsets of recently read runs are kept in a
//! [`FrameCache`] of bounded size, 8 bytes per entry, and extended as the
//! journal grows. They are tied to the run's file *generation*, which
//! erasure and deletion advance when they replace or remove the file (an
//! erased slot drops its salt and content, so every later offset moves).
//!
//! Work that does need a whole journal (verification, evidence bundles,
//! reading a damaged journal's valid prefix) takes its size from a
//! [`ByteBudget`] first, so however many such requests arrive, the
//! journals held at once stay within the budget.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::sync::{Arc, Condvar, Mutex};

use pragmatic::journal::{decode_frame, HEADER_LEN, MAX_RECORD_BYTES};
use pragmatic::{Content, Entry, SlotState};

use crate::error::ApiError;
use crate::fsutil;

/// The most frame offsets kept, in bytes (8 per entry).
pub const FRAME_CACHE_BYTES: u64 = 64 << 20;

/// The most journal bytes held whole at once by readers.
pub const FULL_READ_BUDGET: u64 = 1 << 30;

/// Where each frame of one generation of a journal starts.
#[derive(Debug, Default)]
pub struct Frames {
    generation: u64,
    starts: Vec<u64>,
    /// The end of the last frame walked.
    end: u64,
}

impl Frames {
    fn new(generation: u64) -> Frames {
        Frames {
            generation,
            starts: Vec::new(),
            end: HEADER_LEN as u64,
        }
    }

    /// Walk the length prefixes from the last frame known to `byte_len`.
    /// Reads go through a 64 KiB window, so small frames cost one read per
    /// window rather than one each.
    fn extend(&mut self, file: &File, byte_len: u64) -> io::Result<()> {
        if byte_len < self.end {
            *self = Frames::new(self.generation);
        }
        let mut window = Vec::new();
        let mut window_at = 0u64;
        let mut pos = self.end;
        while pos < byte_len {
            if pos + 4 > byte_len {
                return Err(mismatch(pos));
            }
            if pos < window_at || pos + 4 > window_at + window.len() as u64 {
                let n = (byte_len - pos).min(64 << 10) as usize;
                window.resize(n, 0);
                fsutil::read_exact_at(file, &mut window, pos)?;
                window_at = pos;
            }
            let at = (pos - window_at) as usize;
            let len = u64::from(u32::from_le_bytes(
                window[at..at + 4].try_into().expect("4 bytes"),
            ));
            let next = pos + 4 + len + 32;
            if len > MAX_RECORD_BYTES || next > byte_len {
                return Err(mismatch(pos));
            }
            self.starts.push(pos);
            pos = next;
        }
        self.end = pos;
        Ok(())
    }

    /// `(offset, length)` of the frame at `cursor`.
    fn span(&self, cursor: u64) -> Option<(u64, u64)> {
        let start = *self.starts.get(cursor as usize)?;
        let end = self
            .starts
            .get(cursor as usize + 1)
            .copied()
            .unwrap_or(self.end);
        Some((start, end - start))
    }
}

fn mismatch(pos: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("the journal's frames do not end where its index says (at byte {pos})"),
    )
}

/// Frame offsets of recently read runs, by run id.
#[derive(Default)]
pub struct FrameCache {
    map: HashMap<String, (u64, Arc<Mutex<Frames>>, u64)>,
    tick: u64,
    bytes: u64,
}

impl FrameCache {
    /// The offsets of a run (empty if not cached), marking them used.
    fn handle(&mut self, run_id: &str, generation: u64) -> Arc<Mutex<Frames>> {
        self.tick += 1;
        let tick = self.tick;
        let entry = self
            .map
            .entry(run_id.to_string())
            .or_insert_with(|| (tick, Arc::new(Mutex::new(Frames::new(generation))), 0));
        entry.0 = tick;
        entry.1.clone()
    }

    /// Record a run's offsets' size, and drop the least recently used runs'
    /// while the cache is over its budget.
    fn account(&mut self, run_id: &str, entries: u64) {
        let size = entries * 8;
        if let Some(e) = self.map.get_mut(run_id) {
            self.bytes = self.bytes - e.2 + size;
            e.2 = size;
        }
        while self.bytes > FRAME_CACHE_BYTES && self.map.len() > 1 {
            let Some(oldest) = self
                .map
                .iter()
                .filter(|(id, _)| id.as_str() != run_id)
                .min_by_key(|(_, (t, _, _))| *t)
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            if let Some((_, _, size)) = self.map.remove(&oldest) {
                self.bytes -= size;
            }
        }
    }

    /// Forget a run's offsets (it was deleted).
    pub fn forget(&mut self, run_id: &str) {
        if let Some((_, _, size)) = self.map.remove(run_id) {
            self.bytes -= size;
        }
    }
}

/// The frame spans of `cursors` in one generation of a journal, extending
/// the cached offsets to `byte_len` first. `entries` is the index's count,
/// which the walk must agree with.
pub fn spans(
    cache: &Mutex<FrameCache>,
    run_id: &str,
    generation: u64,
    file: &File,
    byte_len: u64,
    entries: u64,
    cursors: std::ops::Range<u64>,
) -> Result<Vec<(u64, u64)>, ApiError> {
    let handle = cache
        .lock()
        .expect("frame cache")
        .handle(run_id, generation);
    let (spans, walked) = {
        let mut f = handle.lock().unwrap_or_else(|p| p.into_inner());
        if f.generation != generation {
            *f = Frames::new(generation);
        }
        f.extend(file, byte_len)
            .map_err(|e| ApiError::chain_broken(&e.to_string()))?;
        if f.starts.len() as u64 != entries {
            return Err(ApiError::chain_broken(&format!(
                "the journal holds {} frames but the index says {entries}",
                f.starts.len()
            )));
        }
        let spans = cursors.filter_map(|c| f.span(c)).collect::<Vec<_>>();
        (spans, f.starts.len() as u64)
    };
    cache.lock().expect("frame cache").account(run_id, walked);
    Ok(spans)
}

/// Read and decode the frame at `span` as entry `cursor`.
pub fn read_entry(file: &File, cursor: u64, span: (u64, u64)) -> Result<Entry, ApiError> {
    let mut buf = vec![0u8; span.1 as usize];
    fsutil::read_exact_at(file, &mut buf, span.0)?;
    decode_frame(&buf, cursor)
        .map_err(|why| ApiError::chain_broken(&format!("entry {cursor} does not decode: {why}")))
}

/// The stored chain hash of the frame at `span`: its last 32 bytes.
pub fn read_hash(file: &File, span: (u64, u64)) -> Result<[u8; 32], ApiError> {
    let mut hash = [0u8; 32];
    fsutil::read_exact_at(file, &mut hash, span.0 + span.1 - 32)?;
    Ok(hash)
}

/// An entry read from disk, with the content of each ref slot resolved
/// from its target (a frame read on its own cannot resolve refs).
#[derive(Debug, Clone)]
pub struct ReadEntry {
    pub entry: Entry,
    /// For each slot, the content to show when it differs from the one in
    /// the event: a ref's target content.
    pub resolved: Vec<Option<Content>>,
}

impl ReadEntry {
    /// An entry from a parsed journal: its refs are resolved already.
    pub fn parsed(entry: Entry) -> ReadEntry {
        let resolved = vec![None; entry.slots.len()];
        ReadEntry { entry, resolved }
    }

    /// The content of each slot, refs resolved.
    pub fn contents(&self) -> Vec<&Content> {
        self.entry
            .event
            .slot_contents()
            .into_iter()
            .zip(&self.resolved)
            .map(|(c, r)| r.as_ref().unwrap_or(c))
            .collect()
    }
}

/// Resolve the ref slots of `entry` by reading their targets, at most once
/// each per call (`targets` caches them). `span_of` finds a cursor's frame.
pub fn resolve(
    file: &File,
    entry: Entry,
    targets: &mut HashMap<u64, Entry>,
    span_of: &dyn Fn(u64) -> Option<(u64, u64)>,
) -> Result<ReadEntry, ApiError> {
    let mut resolved = vec![None; entry.slots.len()];
    for (i, meta) in entry.slots.iter().enumerate() {
        let (SlotState::Ref, Some((tc, ts))) = (meta.state, meta.ref_target) else {
            continue;
        };
        let target = match targets.entry(tc) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let span = span_of(tc).ok_or_else(|| {
                    ApiError::chain_broken(&format!("a ref names entry {tc}, which is not stored"))
                })?;
                e.insert(read_entry(file, tc, span)?)
            }
        };
        let content = target
            .event
            .slot_contents()
            .get(ts as usize)
            .map(|c| (*c).clone())
            .unwrap_or(Content::Erased);
        resolved[i] = Some(if content.is_sealed() {
            content
        } else {
            Content::Erased
        });
    }
    Ok(ReadEntry { entry, resolved })
}

/// A budget of bytes for journals held whole (see the module
/// documentation). Taking more than the whole budget takes the whole
/// budget, so a journal larger than it is still read, alone.
#[derive(Debug)]
pub struct ByteBudget {
    limit: u64,
    used: Mutex<u64>,
    freed: Condvar,
}

/// Bytes taken from a [`ByteBudget`], returned on drop.
#[derive(Debug)]
pub struct BudgetGuard {
    budget: Arc<ByteBudget>,
    bytes: u64,
}

impl ByteBudget {
    pub fn new(limit: u64) -> ByteBudget {
        ByteBudget {
            limit,
            used: Mutex::new(0),
            freed: Condvar::new(),
        }
    }

    /// Wait until `bytes` (at most the whole budget) are free, and take
    /// them.
    pub fn take(self: &Arc<Self>, bytes: u64) -> BudgetGuard {
        let bytes = bytes.clamp(1, self.limit);
        let mut used = self.used.lock().unwrap_or_else(|p| p.into_inner());
        while *used + bytes > self.limit {
            used = self.freed.wait(used).unwrap_or_else(|p| p.into_inner());
        }
        *used += bytes;
        BudgetGuard {
            budget: self.clone(),
            bytes,
        }
    }

    /// Bytes taken now.
    pub fn in_use(&self) -> u64 {
        *self.used.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        let mut used = self.budget.used.lock().unwrap_or_else(|p| p.into_inner());
        *used -= self.bytes;
        self.budget.freed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::testdir::TestDir;
    use pragmatic::journal::{META, ROOT};
    use pragmatic::{Event, Journal};

    fn journal_file(dir: &std::path::Path, big: usize) -> (Journal, File) {
        let mut j = Journal::new(None);
        j.append(
            META,
            Event::Note {
                kind: "run.start".into(),
                data: r#"{"run_id":"r"}"#.into(),
                payload: vec![],
            },
        )
        .unwrap();
        let repeated = "m".repeat(big);
        for i in 0..5 {
            let v = if i % 2 == 0 {
                repeated.clone()
            } else {
                format!("small {i}")
            };
            j.append(
                ROOT,
                Event::ChannelRecv {
                    channel: "in".into(),
                    value: Content::from(v),
                },
            )
            .unwrap();
        }
        j.mark_persisted(j.len());
        let p = dir.join("j");
        std::fs::write(&p, j.to_bytes()).unwrap();
        (j, File::open(&p).unwrap())
    }

    #[test]
    fn entries_read_by_offset_match_the_parsed_journal() {
        let d = TestDir::new("frames");
        let (j, file) = journal_file(&d, 400);
        let cache = Mutex::new(FrameCache::default());
        let all = spans(&cache, "r", 0, &file, j.byte_len(), j.len(), 0..j.len()).unwrap();
        assert_eq!(all.len() as u64, j.len());
        let mut targets = HashMap::new();
        for (c, span) in all.iter().enumerate() {
            let e = read_entry(&file, c as u64, *span).unwrap();
            assert_eq!(e.hash, j.get(c as u64).unwrap().hash);
            assert_eq!(read_hash(&file, *span).unwrap(), e.hash);
            let span_of = |t: u64| all.get(t as usize).copied();
            let r = resolve(&file, e, &mut targets, &span_of).unwrap();
            // Refs (the repeated 400-byte message) resolve to their target.
            let want: Vec<&Content> = j.get(c as u64).unwrap().event.slot_contents();
            assert_eq!(r.contents(), want, "entry {c}");
        }
        assert_eq!(j.get(3).unwrap().slots[0].state, SlotState::Ref);
        // The count must agree with the index.
        assert!(spans(&cache, "r", 0, &file, j.byte_len(), j.len() + 1, 0..1).is_err());
        // A byte length inside a frame does not match.
        assert!(spans(&cache, "x", 0, &file, j.byte_len() - 1, j.len(), 0..1).is_err());
    }

    #[test]
    fn offsets_follow_growth_and_generations() {
        let d = TestDir::new("frames-gen");
        let (j, file) = journal_file(&d, 10);
        let cache = Mutex::new(FrameCache::default());
        let two =
            (HEADER_LEN + j.frame_bytes(0).unwrap().len() + j.frame_bytes(1).unwrap().len()) as u64;
        assert_eq!(spans(&cache, "r", 0, &file, two, 2, 0..9).unwrap().len(), 2);
        assert_eq!(
            spans(&cache, "r", 0, &file, j.byte_len(), j.len(), 0..9)
                .unwrap()
                .len() as u64,
            j.len()
        );
        // A new generation starts over.
        assert_eq!(spans(&cache, "r", 1, &file, two, 2, 0..9).unwrap().len(), 2);
    }

    #[test]
    fn the_cache_stays_within_its_budget() {
        let mut c = FrameCache::default();
        let per_run = FRAME_CACHE_BYTES / 8 / 4;
        for i in 0..10 {
            let id = format!("r{i}");
            c.handle(&id, 0);
            c.account(&id, per_run);
        }
        assert!(c.bytes <= FRAME_CACHE_BYTES);
        assert!(c.map.contains_key("r9"));
        assert!(!c.map.contains_key("r0"));
    }

    #[test]
    fn the_budget_waits_for_room() {
        let b = Arc::new(ByteBudget::new(100));
        let a = b.take(60);
        let (tx, rx) = std::sync::mpsc::channel();
        let b2 = b.clone();
        let waiter = std::thread::spawn(move || {
            // More than the whole budget takes the whole budget.
            let big = b2.take(1_000);
            tx.send(b2.in_use()).unwrap();
            drop(big);
        });
        assert!(rx
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err());
        drop(a);
        assert_eq!(rx.recv().unwrap(), 100);
        waiter.join().unwrap();
        assert_eq!(b.in_use(), 0);
    }
}
