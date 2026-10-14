//! Erasure (spec 2.13): drop the content of chosen slots while every chain
//! hash still verifies.
//!
//! [`Journal::erase`] builds the complete new file in memory: every original
//! frame, with the chosen sealed slots changed to state 2 (salt and content
//! dropped, commitment kept), followed by an `erasure` note chained on the
//! old head. It then reads that file back and checks it against the original
//! before handing it out, so a bug here can never be committed:
//!
//! - the entry count is the old count plus one;
//! - every original chain hash and every commitment is unchanged;
//! - the only state change is sealed to erased, on exactly the chosen slots.
//!
//! Committing the bytes atomically is the storage layer's job
//! ([`Sink::rewrite`](crate::backend::Sink::rewrite): temp file, fsync,
//! rename, directory fsync, reopen).
//!
//! Refs are never rewritten. A ref to an erased slot stays a ref and reads
//! as erased ("erased through its target"), which is how one erasure covers
//! every deduplicated copy of a message.

use std::collections::BTreeSet;

use crate::fault::Fault;
use crate::json::Json;
use crate::value::Value;

use super::codec;
use super::{note, Content, Cursor, Entry, Journal, SlotState, FORMAT, FORMAT1_READ_ONLY, META};

/// Which slots to erase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EraseSelector {
    /// Explicit `(cursor, slot)` pairs. A pair naming a ref erases the ref's
    /// target (and with it every other ref to that target). Pairs that are
    /// already erased are skipped, so repeating an erasure is harmless.
    Slots(Vec<(Cursor, u8)>),
    /// Every sealed slot whose content contains these bytes, and every
    /// sealed slot holding a streamed model reply whose reassembled text
    /// contains them ([`crate::redact::stream`]): a value the model
    /// repeated back arrives split across token deltas, and a data subject
    /// request must reach it there too. The whole slot is erased.
    Match(Vec<u8>),
    /// Every sealed slot (shredding a run).
    All,
}

/// What the `erasure` note records about who erased and why.
///
/// `by` is a token id, or `local:<os-user>@<host>` for a local erasure;
/// never a name or an email address. The free-text `reason` goes into the
/// note's payload slot (so it can itself be erased later); everything else
/// is structural.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErasureNote {
    pub by: String,
    pub authenticated: bool,
    pub reason_code: String,
    pub access_log_cursor: Option<u64>,
    pub reason: String,
}

impl ErasureNote {
    /// A note for an erasure performed locally (for example by
    /// `pragmatic erase`): `by` is `local:<os-user>@<host>` and
    /// `authenticated` is false.
    pub fn local(reason_code: &str, reason: &str) -> ErasureNote {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        ErasureNote {
            by: format!("local:{user}@{}", crate::sys::host_name()),
            authenticated: false,
            reason_code: reason_code.to_string(),
            access_log_cursor: None,
            reason: reason.to_string(),
        }
    }

    /// The note's compact JSON data, keys sorted.
    fn data(&self, slots: &[(Cursor, u8)]) -> String {
        let slots = slots
            .iter()
            .map(|&(c, s)| Json::Array(vec![c.into(), s.into()]))
            .collect();
        Json::Object(vec![
            (
                "access_log_cursor".into(),
                self.access_log_cursor.map_or(Json::Null, Json::from),
            ),
            ("authenticated".into(), self.authenticated.into()),
            ("by".into(), self.by.as_str().into()),
            ("reason_code".into(), self.reason_code.as_str().into()),
            ("slots".into(), Json::Array(slots)),
        ])
        .to_string()
    }
}

/// A validated erasure, ready to commit.
#[derive(Clone, Debug)]
pub struct Erasure {
    /// The complete new journal file.
    pub file: Vec<u8>,
    /// The journal those bytes parse to. Use it in place of the old one
    /// once `file` is committed.
    pub journal: Journal,
    /// The slots changed from sealed to erased, sorted.
    pub slots: Vec<(Cursor, u8)>,
    /// The cursor of the `erasure` note.
    pub note_cursor: Cursor,
}

impl Journal {
    /// Build and validate the erased file (spec 2.13 steps 1 and 2).
    ///
    /// The journal must be format 2, stored (not from an evidence bundle)
    /// and fully persisted. Selecting nothing that is still sealed is an
    /// error, as is naming a slot that does not exist. `at` stamps the note.
    pub fn erase(
        &self,
        what: &EraseSelector,
        note: &ErasureNote,
        at: u64,
    ) -> Result<Erasure, Fault> {
        if self.format != FORMAT {
            return Err(Fault::Unsupported(FORMAT1_READ_ONLY.into()));
        }
        if self.allow_withheld {
            return Err(Fault::Unsupported(
                "an evidence journal cannot be erased".into(),
            ));
        }
        if self.pending().is_some() {
            return Err(Fault::Unsupported(
                "erasure needs a fully persisted journal".into(),
            ));
        }
        let targets = self.select(what)?;
        if targets.is_empty() {
            return Err(Fault::Unsupported(
                "nothing to erase: no sealed slot matches".into(),
            ));
        }
        let slots: Vec<(Cursor, u8)> = targets.iter().copied().collect();

        let mut next = self.clone();
        next.erase_in_place(&targets);
        let payload = if note.reason.is_empty() {
            Vec::new()
        } else {
            vec![Value::from(note.reason.as_str())]
        };
        let note_cursor =
            next.append_server_note(at, note::ERASURE, &note.data(&slots), payload)?;
        let file = next.to_bytes();

        let mut parsed = Journal::parse(&file, self.key.as_deref())
            .map_err(|e| invalid(&format!("the new file does not read back: {e}")))?;
        if parsed.tail_len != 0 {
            return Err(invalid("the new file has trailing bytes"));
        }
        validate(self, &parsed.journal, &targets)?;
        parsed.journal.clock = self.clock;
        Ok(Erasure {
            file,
            journal: parsed.journal,
            slots,
            note_cursor,
        })
    }

    /// The sealed slots an erasure of `what` would erase, in order, without
    /// erasing anything: what a confirmation lists before the erasure acts.
    /// A ref names its target, as [`EraseSelector::Slots`] does.
    pub fn erase_targets(&self, what: &EraseSelector) -> Result<Vec<(Cursor, u8)>, Fault> {
        self.select(what).map(|s| s.into_iter().collect())
    }

    /// The sealed slots `what` selects.
    fn select(&self, what: &EraseSelector) -> Result<BTreeSet<(Cursor, u8)>, Fault> {
        let mut out = BTreeSet::new();
        match what {
            EraseSelector::Slots(pairs) => {
                for &(c, s) in pairs {
                    let entry = self.get(c).ok_or_else(|| {
                        Fault::Unsupported(format!("erase names cursor {c}, which does not exist"))
                    })?;
                    let meta = entry.slots.get(s as usize).ok_or_else(|| {
                        Fault::Unsupported(format!(
                            "erase names slot {s} of cursor {c}, which does not exist"
                        ))
                    })?;
                    let (c, s, state) = match meta.ref_target {
                        Some((tc, ts)) if meta.state == SlotState::Ref => {
                            (tc, ts, self.entries[tc as usize].slots[ts as usize].state)
                        }
                        _ => (c, s, meta.state),
                    };
                    if state == SlotState::Sealed {
                        out.insert((c, s));
                    }
                }
            }
            EraseSelector::Match(needle) => {
                if needle.is_empty() {
                    return Err(Fault::Unsupported("erase match text is empty".into()));
                }
                self.for_each_sealed(|c, s, bytes| {
                    if contains(bytes, needle) || crate::redact::stream::contains(bytes, needle) {
                        out.insert((c, s));
                    }
                });
            }
            EraseSelector::All => self.for_each_sealed(|c, s, _| {
                out.insert((c, s));
            }),
        }
        Ok(out)
    }

    fn for_each_sealed(&self, mut f: impl FnMut(Cursor, u8, &[u8])) {
        for entry in &self.entries {
            for (k, (meta, content)) in entry
                .slots
                .iter()
                .zip(entry.event.slot_contents())
                .enumerate()
            {
                if let (SlotState::Sealed, Some(v)) = (meta.state, content.value()) {
                    f(entry.cursor, k as u8, v.as_bytes());
                }
            }
        }
    }

    /// Change the targets to erased, and every ref to a target to read as
    /// erased. Chain hashes are untouched because skeletons only see
    /// commitments.
    fn erase_in_place(&mut self, targets: &BTreeSet<(Cursor, u8)>) {
        for i in 0..self.entries.len() {
            let cursor = i as Cursor;
            let entry = &mut self.entries[i];
            let erase_here: Vec<usize> = entry
                .slots
                .iter()
                .enumerate()
                .filter(|(k, meta)| {
                    targets.contains(&(cursor, *k as u8))
                        || meta.ref_target.is_some_and(|t| targets.contains(&t))
                })
                .map(|(k, _)| k)
                .collect();
            if erase_here.is_empty() {
                continue;
            }
            let mut contents = entry.event.slot_contents_mut();
            for &k in &erase_here {
                *contents[k] = Content::Erased;
                if entry.slots[k].state == SlotState::Sealed {
                    entry.slots[k].state = SlotState::Erased;
                    self.salts[i][k] = None;
                }
            }
        }
        self.dedup.clear();
        for i in 0..self.entries.len() {
            let entry = self.entries[i].clone();
            self.index_entry(&entry);
        }
    }
}

/// Spec 2.13 step 2: the new journal against the old.
fn validate(old: &Journal, new: &Journal, targets: &BTreeSet<(Cursor, u8)>) -> Result<(), Fault> {
    if new.len() != old.len() + 1 {
        return Err(invalid("the entry count is not the old count plus one"));
    }
    for (o, n) in old.entries.iter().zip(&new.entries) {
        if o.hash != n.hash {
            return Err(invalid("a chain hash changed"));
        }
        if o.slots.len() != n.slots.len() {
            return Err(invalid("a slot count changed"));
        }
        for (k, (os, ns)) in o.slots.iter().zip(&n.slots).enumerate() {
            if os.commitment != ns.commitment {
                return Err(invalid("a commitment changed"));
            }
            let chosen = targets.contains(&(o.cursor, k as u8));
            let expected = if chosen { SlotState::Erased } else { os.state };
            if ns.state != expected || (chosen && os.state != SlotState::Sealed) {
                return Err(invalid("a slot state changed other than sealed to erased"));
            }
        }
    }
    let last = new.entries.last().expect("checked length");
    if last.branch != META || last.event.note_kind() != Some(note::ERASURE) {
        return Err(invalid("the last frame is not the erasure note"));
    }
    if new.verify().is_err() {
        return Err(invalid("the new journal does not verify"));
    }
    Ok(())
}

fn invalid(why: &str) -> Fault {
    Fault::Io(format!("erasure validation failed: {why}"))
}

/// True if `needle` occurs in `hay`.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.len() > hay.len() {
        return false;
    }
    let first = needle[0];
    let last_start = hay.len() - needle.len();
    let mut i = 0;
    while i <= last_start {
        match hay[i..=last_start].iter().position(|&b| b == first) {
            Some(off) => {
                let at = i + off;
                if &hay[at..at + needle.len()] == needle {
                    return true;
                }
                i = at + 1;
            }
            None => return false,
        }
    }
    false
}

/// `(cursor, slot)` pairs.
type SlotList = Vec<(Cursor, u8)>;

/// The slots an `erasure` note lists. `Err` carries the in-range ones when
/// the note is invalid: unreadable data, a malformed pair, or a pair that
/// does not name an existing slot earlier than the note.
pub(crate) fn listed_slots(
    data: &str,
    note_cursor: Cursor,
    entries: &[Entry],
) -> Result<SlotList, SlotList> {
    let Ok(doc) = codec::strict_json(data.as_bytes()) else {
        return Err(Vec::new());
    };
    let Some(pairs) = doc.get("slots").and_then(Json::as_array) else {
        return Err(Vec::new());
    };
    let mut ok = Vec::with_capacity(pairs.len());
    let mut bad = false;
    for pair in pairs {
        let parsed = pair.as_array().and_then(|p| match p {
            [c, s] => Some((c.as_u64()?, u8::try_from(s.as_u64()?).ok()?)),
            _ => None,
        });
        match parsed {
            Some((c, s))
                if c < note_cursor
                    && entries
                        .get(c as usize)
                        .is_some_and(|e| (s as usize) < e.slots.len()) =>
            {
                ok.push((c, s));
            }
            _ => bad = true,
        }
    }
    if bad {
        Err(ok)
    } else {
        Ok(ok)
    }
}

#[cfg(test)]
mod tests {
    use super::contains;

    #[test]
    fn substring_search() {
        assert!(contains(b"hello world", b"world"));
        assert!(contains(b"hello world", b"hello world"));
        assert!(contains(b"aaab", b"ab"));
        assert!(!contains(b"hello", b"world"));
        assert!(!contains(b"ab", b"abc"));
        assert!(contains(b"xyz", b"z"));
    }
}
