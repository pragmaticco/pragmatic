//! Building bundles from local journals, and withholding slots.
//!
//! A local bundle ([`Bundle::local`]) is what `pragmatic evidence` writes
//! for a run journaled to a directory: the journal, its records, and no
//! anchors (local anchoring is deferred to 0.7), unsigned. It still
//! verifies end to end (chain, commitments, erasure accounting, records),
//! and the verdict says plainly that nothing anchors it in time.

use std::collections::BTreeSet;

use crate::fault::Fault;
use crate::journal::{Cursor, Journal, SlotState, FORMAT as JOURNAL_FORMAT};
use crate::redact::{self, binary, Kind};

use super::{patterns_sha256, Bundle, JournalData, JournalEncoding, Record, Redaction, FORMAT};

/// What to withhold when building a bundle. A withheld slot is left out
/// whole (state 3, commitment only); content is never altered inside a
/// slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Redact {
    /// Withhold nothing.
    None,
    /// Withhold every slot in which one of these detectors finds a match,
    /// and every slot that holds or may hold binary content (attachments
    /// are never scanned, so they are never assumed clean).
    Detectors(Vec<Kind>),
    /// Withhold every slot that holds binary content (design 4.10), or may:
    /// a slot that starts like JSON but could not be read to its end is
    /// withheld too, since what the scan did not reach is never assumed to
    /// be free of attachments.
    Binary,
    /// Withhold every slot: the bundle shows structure, timing and
    /// integrity, and no content at all.
    All,
}

impl Redact {
    /// The `redaction.mode` name.
    pub fn mode(&self) -> &'static str {
        match self {
            Redact::None => "none",
            Redact::Detectors(_) => "detectors",
            Redact::Binary => "binary",
            Redact::All => "all",
        }
    }

    /// True if `bytes` (one slot's content) must be withheld.
    pub fn withholds(&self, bytes: &[u8]) -> bool {
        match self {
            Redact::None => false,
            Redact::All => true,
            Redact::Binary => binary::scan(bytes).may_hold_binary(),
            Redact::Detectors(kinds) => {
                let scanned = binary::scan(bytes);
                scanned.may_hold_binary()
                    || scanned
                        .text
                        .is_some_and(|t| !redact::find(&t, kinds).is_empty())
            }
        }
    }

    fn redaction(&self) -> Redaction {
        let detectors = match self {
            Redact::Detectors(kinds) => kinds.iter().map(|k| k.name().to_string()).collect(),
            _ => Vec::new(),
        };
        Redaction {
            mode: self.mode().to_string(),
            detectors,
            patterns_sha256: patterns_sha256(&[]),
        }
    }
}

impl Bundle {
    /// An unanchored, unsigned bundle of a local journal.
    ///
    /// `journal` is the journal file as stored. Only its valid prefix is
    /// used (a torn tail is ignored, as every reader does); it must be a
    /// format 2, unkeyed journal whose `run.start` names `run_id`. Slots
    /// are withheld as `redact` says.
    pub fn local(journal: &[u8], run_id: &str, redact: &Redact) -> Result<Bundle, Fault> {
        let parsed = Journal::parse(journal, None)?;
        let j = parsed.journal;
        if j.format() != JOURNAL_FORMAT {
            return Err(Fault::Unsupported(
                "evidence bundles carry format 2 journals; this run is format 1 (read-only)".into(),
            ));
        }
        match j.run_start_id() {
            Some(id) if id == run_id => {}
            Some(id) => {
                return Err(Fault::Unsupported(format!(
                    "the journal belongs to run {id:?}, not {run_id:?}"
                )))
            }
            None => {
                return Err(Fault::Unsupported(
                    "the journal has no run.start note, so it cannot be tied to a run".into(),
                ))
            }
        }
        let chosen = slots_to_withhold(&j, redact);
        let withheld = j.withhold(&chosen)?;
        let mut bundle = Bundle {
            generated_at: super::time::now_rfc3339(),
            generator: format!("pragmatic {}", env!("CARGO_PKG_VERSION")),
            requested_by: local_identity(),
            run_id: run_id.to_string(),
            anchor_id: None,
            independent: false,
            journal: JournalData {
                encoding: JournalEncoding::Base64,
                bytes: Vec::new(),
                entries: 0,
                head: [0; 32],
            },
            redaction: redact.redaction(),
            redacted_slots: Vec::new(),
            records: Vec::new(),
            anchors: Vec::new(),
            latest_checkpoint: None,
            verification_spec: None,
            signature: None,
        };
        bundle.set_journal(withheld.file, &withheld.journal);
        debug_assert_eq!(FORMAT, "pragmatic-evidence/1");
        Ok(bundle)
    }

    /// Withhold more slots (a ref names its target). The journal, its
    /// records and `redacted_slots` are rebuilt; anchors stay valid because
    /// chain hashes do not change. A signature no longer covers the bundle,
    /// so it is dropped. Returns the slots that changed.
    pub fn withhold(&mut self, slots: &[(Cursor, u8)]) -> Result<Vec<(Cursor, u8)>, Fault> {
        if self.journal.bytes.is_empty() {
            return Err(Fault::Unsupported(
                "the bundle's journal is not attached".into(),
            ));
        }
        let parsed = Journal::parse_evidence(&self.journal.bytes)?;
        if parsed.tail_len != 0 {
            return Err(Fault::Unsupported(
                "the bundle's journal has trailing bytes".into(),
            ));
        }
        let withheld = parsed.journal.withhold(slots)?;
        self.set_journal(withheld.file, &withheld.journal);
        self.signature = None;
        Ok(withheld.slots)
    }

    /// Replace the journal and everything derived from it.
    fn set_journal(&mut self, file: Vec<u8>, journal: &Journal) {
        self.journal.bytes = file;
        self.journal.entries = journal.len();
        self.journal.head = journal.head();
        if let JournalEncoding::File { sha256, .. } = &mut self.journal.encoding {
            *sha256 = crate::sha256::sha256(&self.journal.bytes);
        }
        self.records = journal
            .entries()
            .iter()
            .filter_map(Record::of_entry)
            .collect();
        self.redacted_slots = withheld_slots(journal);
    }
}

/// Every state 3 slot of a journal, sorted.
pub(crate) fn withheld_slots(journal: &Journal) -> Vec<(u64, u8)> {
    let mut out = Vec::new();
    for e in journal.entries() {
        for (k, meta) in e.slots.iter().enumerate() {
            if meta.state == SlotState::Withheld {
                out.push((e.cursor, k as u8));
            }
        }
    }
    out
}

/// The sealed slots `redact` withholds.
fn slots_to_withhold(journal: &Journal, redact: &Redact) -> Vec<(Cursor, u8)> {
    if *redact == Redact::None {
        return Vec::new();
    }
    let mut out = BTreeSet::new();
    for e in journal.entries() {
        for (k, (meta, content)) in e.slots.iter().zip(e.event.slot_contents()).enumerate() {
            if meta.state != SlotState::Sealed {
                continue;
            }
            if let Some(v) = content.value() {
                if redact.withholds(v.as_bytes()) {
                    out.insert((e.cursor, k as u8));
                }
            }
        }
    }
    out.into_iter().collect()
}

/// `local:<os-user>@<host>`, the `requested_by` of a local bundle: the
/// same form `pragmatic erase` writes as `by`, never a name or an email.
pub(crate) fn local_identity() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    format!("local:{user}@{}", crate::sys::host_name())
}
