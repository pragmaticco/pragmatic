//! Withholding (spec 5.1): the evidence form of a journal, with chosen
//! slots left out whole.
//!
//! An evidence bundle may have to leave content out: personal data an
//! auditor is not entitled to, attachments, or everything but the
//! structure. Content is never altered inside a slot, because a changed
//! slot would no longer match its commitment and the bundle would prove
//! nothing about it. Instead the slot is *withheld* (state 3): its salt and
//! content are dropped and its commitment stays, exactly like erasure, so
//! every chain hash still verifies and a party holding the content and the
//! salt could still show it was the committed one.
//!
//! The difference from erasure is where it happens. Erasure rewrites the
//! stored journal and records an `erasure` note; withholding only shapes a
//! copy for one bundle, appends nothing, and is valid only inside a bundle
//! (a stored journal with a state 3 slot is rejected by
//! [`Journal::parse`]). The bundle lists the withheld slots in
//! `redacted_slots`, and a verifier checks that list against the journal.
//!
//! Refs are never rewritten. Naming a ref withholds its target, and every
//! ref to a withheld target then reads as withheld too, so one slot never
//! leaks through a deduplicated copy of it.

use std::collections::BTreeSet;

use crate::fault::Fault;

use super::{Content, Cursor, Journal, SlotState, FORMAT, FORMAT1_READ_ONLY};

/// The evidence form of a journal with some slots withheld.
#[derive(Clone, Debug)]
pub struct Withheld {
    /// The complete journal file for the bundle (unkeyed, format 2).
    pub file: Vec<u8>,
    /// The journal those bytes parse to with [`Journal::parse_evidence`].
    pub journal: Journal,
    /// The slots changed from sealed to withheld by this call, sorted.
    pub slots: Vec<(Cursor, u8)>,
}

impl Journal {
    /// Build the evidence form of this journal with the named slots
    /// withheld, and check it before handing it out.
    ///
    /// The journal must be format 2 and unkeyed (evidence journals are
    /// always unkeyed: an auditor has no key). It may itself come from a
    /// bundle, so a bundle can withhold more. A pair naming a ref withholds
    /// the ref's target; pairs naming slots that are already erased or
    /// withheld change nothing. Naming a slot that does not exist is an
    /// error.
    ///
    /// The result is validated the way an erasure is: it reads back with
    /// [`Journal::parse_evidence`] with no trailing bytes, has the same
    /// entries with the same chain hashes and commitments, and differs only
    /// in the chosen slots going from sealed to withheld.
    pub fn withhold(&self, slots: &[(Cursor, u8)]) -> Result<Withheld, Fault> {
        if self.format != FORMAT {
            return Err(Fault::Unsupported(FORMAT1_READ_ONLY.into()));
        }
        if self.is_keyed() {
            return Err(Fault::Unsupported(
                "a keyed journal cannot go into an evidence bundle: verifying it would need the key"
                    .into(),
            ));
        }
        let targets = self.withhold_targets(slots)?;
        let mut next = self.clone();
        next.allow_withheld = true;
        next.withhold_in_place(&targets);
        let file = next.to_bytes();
        let parsed = Journal::parse_evidence(&file)
            .map_err(|e| invalid(&format!("the evidence journal does not read back: {e}")))?;
        if parsed.tail_len != 0 {
            return Err(invalid("the evidence journal has trailing bytes"));
        }
        validate(self, &parsed.journal, &targets)?;
        Ok(Withheld {
            file,
            journal: parsed.journal,
            slots: targets.into_iter().collect(),
        })
    }

    /// The sealed slots the pairs name, with refs resolved to their targets.
    fn withhold_targets(&self, pairs: &[(Cursor, u8)]) -> Result<BTreeSet<(Cursor, u8)>, Fault> {
        let mut out = BTreeSet::new();
        for &(c, s) in pairs {
            let entry = self.get(c).ok_or_else(|| {
                Fault::Unsupported(format!("withhold names cursor {c}, which does not exist"))
            })?;
            let meta = entry.slots.get(s as usize).ok_or_else(|| {
                Fault::Unsupported(format!(
                    "withhold names slot {s} of cursor {c}, which does not exist"
                ))
            })?;
            let (c, s) = match meta.ref_target {
                Some(target) if meta.state == SlotState::Ref => target,
                _ => (c, s),
            };
            if self.entries[c as usize].slots[s as usize].state == SlotState::Sealed {
                out.insert((c, s));
            }
        }
        Ok(out)
    }

    /// Change the targets to withheld and every ref to a target to read as
    /// withheld. Chain hashes are untouched: skeletons only see commitments.
    fn withhold_in_place(&mut self, targets: &BTreeSet<(Cursor, u8)>) {
        for i in 0..self.entries.len() {
            let cursor = i as Cursor;
            let entry = &mut self.entries[i];
            let hit: Vec<usize> = entry
                .slots
                .iter()
                .enumerate()
                .filter(|(k, meta)| {
                    targets.contains(&(cursor, *k as u8))
                        || meta.ref_target.is_some_and(|t| targets.contains(&t))
                })
                .map(|(k, _)| k)
                .collect();
            if hit.is_empty() {
                continue;
            }
            let mut contents = entry.event.slot_contents_mut();
            for &k in &hit {
                *contents[k] = Content::Withheld;
                if entry.slots[k].state == SlotState::Sealed {
                    entry.slots[k].state = SlotState::Withheld;
                    self.salts[i][k] = None;
                }
            }
        }
        self.dedup.clear();
    }
}

/// The evidence journal against the original.
fn validate(old: &Journal, new: &Journal, targets: &BTreeSet<(Cursor, u8)>) -> Result<(), Fault> {
    if new.len() != old.len() {
        return Err(invalid("the entry count changed"));
    }
    for (o, n) in old.entries.iter().zip(&new.entries) {
        if o.hash != n.hash || o.slots.len() != n.slots.len() {
            return Err(invalid("a chain hash or slot count changed"));
        }
        for (k, (os, ns)) in o.slots.iter().zip(&n.slots).enumerate() {
            if os.commitment != ns.commitment {
                return Err(invalid("a commitment changed"));
            }
            let chosen = targets.contains(&(o.cursor, k as u8));
            let expected = if chosen {
                SlotState::Withheld
            } else {
                os.state
            };
            if ns.state != expected {
                return Err(invalid(
                    "a slot state changed other than sealed to withheld",
                ));
            }
        }
    }
    if new.verify().is_err() {
        return Err(invalid("the evidence journal does not verify"));
    }
    Ok(())
}

fn invalid(why: &str) -> Fault {
    Fault::Io(format!("withholding failed validation: {why}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{note, Event, META, ROOT};
    use crate::value::Value;

    fn journal() -> Journal {
        let mut j = Journal::new(None);
        let start =
            r#"{"format":2,"labels":{},"nonce":"00","run_id":"w","sdk":"t","sdk_version":"0"}"#;
        j.append(
            META,
            Event::Note {
                kind: note::RUN_START.into(),
                data: start.into(),
                payload: vec![],
            },
        )
        .unwrap();
        let long = "x".repeat(300);
        for _ in 0..2 {
            j.append(
                ROOT,
                Event::ChannelRecv {
                    channel: "in".into(),
                    value: Value::from(long.as_str()).into(),
                },
            )
            .unwrap();
        }
        j.append(
            ROOT,
            Event::EffectIntent {
                name: "send".into(),
                arg: "secret@example.com".into(),
            },
        )
        .unwrap();
        j.mark_persisted(j.len());
        j
    }

    #[test]
    fn withheld_slots_keep_the_chain_and_read_back_only_as_evidence() {
        let j = journal();
        let w = j.withhold(&[(3, 0)]).unwrap();
        assert_eq!(w.slots, vec![(3, 0)]);
        assert_eq!(w.journal.head(), j.head());
        assert_eq!(w.journal.entries()[3].slots[0].state, SlotState::Withheld);
        assert!(matches!(
            &w.journal.entries()[3].event,
            Event::EffectIntent {
                arg: Content::Withheld,
                ..
            }
        ));
        assert!(!String::from_utf8_lossy(&w.file).contains("secret@example.com"));
        // A stored journal never holds state 3: the frame does not read.
        let stored = Journal::parse(&w.file, None);
        assert!(stored.map_or(true, |p| p.journal.len() < j.len()));
    }

    #[test]
    fn naming_a_ref_withholds_its_target_and_every_copy() {
        let j = journal();
        assert_eq!(j.entries()[2].slots[0].state, SlotState::Ref);
        let w = j.withhold(&[(2, 0)]).unwrap();
        assert_eq!(w.slots, vec![(1, 0)]);
        assert_eq!(w.journal.entries()[1].slots[0].state, SlotState::Withheld);
        assert_eq!(w.journal.entries()[2].slots[0].state, SlotState::Ref);
        assert!(matches!(
            &w.journal.entries()[2].event,
            Event::ChannelRecv {
                value: Content::Withheld,
                ..
            }
        ));
        assert!(!String::from_utf8_lossy(&w.file).contains("xxxxxxxx"));
    }

    #[test]
    fn withholding_again_is_harmless_and_unknown_slots_are_errors() {
        let j = journal();
        let w = j.withhold(&[(3, 0)]).unwrap();
        let again = w.journal.withhold(&[(3, 0), (1, 0)]).unwrap();
        assert_eq!(again.slots, vec![(1, 0)]);
        assert!(j.withhold(&[(9, 0)]).is_err());
        assert!(j.withhold(&[(3, 1)]).is_err());
        assert!(Journal::new(Some(b"k")).withhold(&[]).is_err());
    }
}
