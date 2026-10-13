//! Tests for journal format 2: encoding, canonical decoding, commitments and
//! refs, keying, torn tails versus corruption, erasure, format 1 and limits.

use super::codec::{self, DecodeOpts, SALT_LEN};
use super::*;
use crate::sha256::{hmac_sha256, sha256};

const AT: u64 = 1_760_000_000_000_000_000;

fn fixed_clock() -> u64 {
    AT
}

fn journal(key: Option<&[u8]>) -> Journal {
    let mut j = Journal::new(key);
    j.set_clock(fixed_clock);
    j
}

/// One event of every kind (and every effect outcome), each on a branch it
/// may legally sit on.
fn every_kind() -> Vec<(Branch, Event)> {
    vec![
        (
            META.to_vec(),
            Event::Note {
                kind: note::RUN_START.into(),
                data: r#"{"format":2,"run_id":"r"}"#.into(),
                payload: vec![r#"{"subjects":["u1"]}"#.into()],
            },
        ),
        (
            vec![],
            Event::DrawIntent {
                provenance: "anthropic".into(),
                parts: vec!["POST /v1/messages {}".into(), "hello".into()],
            },
        ),
        (
            vec![],
            Event::DrawResult {
                intent: 1,
                meta: r#"{"outcome":"ok","usage":{"input_tokens":3}}"#.into(),
                head: r#"{"status":200}"#.into(),
                body: "hi there".into(),
            },
        ),
        (
            vec![0],
            Event::ChannelRecv {
                channel: "inbox".into(),
                value: "a message".into(),
            },
        ),
        (
            vec![0, 3],
            Event::EffectIntent {
                name: "send_email".into(),
                arg: r#"{"to":"x"}"#.into(),
            },
        ),
        (
            vec![0, 3],
            Event::EffectResult {
                intent: 4,
                outcome: EffectOutcome::Ok,
                error_kind: String::new(),
                payload: Some("sent".into()),
            },
        ),
        (
            vec![0, 3],
            Event::EffectResult {
                intent: 4,
                outcome: EffectOutcome::Failed,
                error_kind: "ValueError".into(),
                payload: Some("bad address".into()),
            },
        ),
        (
            vec![0, 3],
            Event::EffectResult {
                intent: 4,
                outcome: EffectOutcome::Compensated,
                error_kind: String::new(),
                payload: None,
            },
        ),
        (vec![], Event::Clock { nanos: 123_456 }),
        (
            vec![],
            Event::Program {
                name: "agent".into(),
                hash: "3f2a".into(),
            },
        ),
        (
            vec![],
            Event::Fork {
                base: 0,
                children: 2,
            },
        ),
        (
            vec![],
            Event::Marker {
                name: "fix-retry".into(),
            },
        ),
        (
            vec![],
            Event::Random {
                source: "randint".into(),
                args: "[1,6]".into(),
                value: "4".into(),
            },
        ),
        (
            vec![],
            Event::Random {
                source: "bytes".into(),
                args: "[3]".into(),
                value: Content::from(vec![0u8, 255, 7]),
            },
        ),
        (
            vec![2],
            Event::Refusal {
                step: refusal::RECV.into(),
                name: "approvals".into(),
                fault: refusal::TIMEOUT.into(),
            },
        ),
        (
            META.to_vec(),
            Event::Note {
                kind: note::ATTEMPT_START.into(),
                data: "{}".into(),
                payload: vec![],
            },
        ),
    ]
}

fn full_journal(key: Option<&[u8]>) -> Journal {
    let mut j = journal(key);
    for (b, e) in every_kind() {
        j.append(&b, e).unwrap();
    }
    j
}

fn reparse(j: &Journal, key: Option<&[u8]>) -> Journal {
    let parsed = Journal::parse(&j.to_bytes(), key).unwrap();
    assert_eq!(parsed.tail_len, 0);
    assert_eq!(parsed.valid_len, j.byte_len());
    parsed.journal
}

/// `(frame start, record length)` of every frame of a format 2 file.
fn frames(file: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut pos = HEADER_LEN;
    while pos + 4 <= file.len() {
        let len = u32::from_le_bytes(file[pos..pos + 4].try_into().unwrap()) as usize;
        if pos + 4 + len + 32 > file.len() {
            break;
        }
        out.push((pos, len));
        pos += 4 + len + 32;
    }
    out
}

/// The file with frame `cursor`'s record replaced by `rec`, keeping its
/// stored hash.
fn replace_record(file: &[u8], cursor: usize, rec: &[u8]) -> Vec<u8> {
    let (start, len) = frames(file)[cursor];
    let mut out = file[..start].to_vec();
    out.extend_from_slice(&(rec.len() as u32).to_le_bytes());
    out.extend_from_slice(rec);
    out.extend_from_slice(&file[start + 4 + len..]);
    out
}

fn record(file: &[u8], cursor: usize) -> Vec<u8> {
    let (start, len) = frames(file)[cursor];
    file[start + 4..start + 4 + len].to_vec()
}

fn corrupt_at(result: Result<Parsed, JournalError>) -> (Cursor, String) {
    match result {
        Err(JournalError::Corrupt { cursor, reason }) => (cursor, reason),
        Err(other) => panic!("expected corruption, got {other}"),
        Ok(p) => panic!(
            "expected corruption, parsed {} entries with a {}-byte tail",
            p.journal.len(),
            p.tail_len
        ),
    }
}

fn occurrences(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

// ---------------------------------------------------------------------------
// Round trips
// ---------------------------------------------------------------------------

#[test]
fn every_kind_round_trips_through_bytes() {
    for key in [None, Some(&b"hmac key"[..])] {
        let j = full_journal(key);
        let file = j.to_bytes();
        let back = reparse(&j, key);
        assert_eq!(back.entries(), j.entries());
        assert_eq!(back.to_bytes(), file, "re-encoding is byte-identical");
        assert_eq!(back.head(), j.head());
        assert!(back.verify().is_ok());
        assert!(back.audit().is_ok());
        for e in back.entries() {
            assert_eq!(e.at, AT);
        }
    }
}

#[test]
fn pending_frames_are_exactly_the_file_suffix() {
    let mut j = journal(None);
    for (b, e) in every_kind().into_iter().take(4) {
        j.append(&b, e).unwrap();
    }
    let (at, frames, head) = j.pending().unwrap();
    assert_eq!((at, head), (0, j.head()));
    let mut file = header(0).to_vec();
    file.extend_from_slice(frames);
    assert_eq!(file, j.to_bytes());

    j.mark_persisted(1);
    let (at, rest, _) = j.pending().unwrap();
    assert_eq!(at, 1);
    assert_eq!(rest, &file[16 + j.frame_bytes(0).unwrap().len()..]);
    j.mark_persisted(j.len());
    assert!(j.pending().is_none());
    assert_eq!(j.persisted_len(), 4);
    // Clamped, never backwards.
    j.mark_persisted(0);
    assert_eq!(j.persisted_len(), 4);
}

#[test]
fn explicit_at_and_branches_are_kept() {
    let mut j = journal(None);
    let deep: Vec<u32> = (0..32).collect();
    j.append_at(7, &deep, Event::Clock { nanos: 1 }).unwrap();
    j.append_at(u64::MAX, &[0xFFFF_FFFE], Event::Clock { nanos: 2 })
        .unwrap();
    let back = reparse(&j, None);
    assert_eq!(back.entries()[0].at, 7);
    assert_eq!(back.entries()[0].branch, deep);
    assert_eq!(back.entries()[1].at, u64::MAX);
}

#[test]
fn program_entries_exclude_meta() {
    let j = full_journal(None);
    let program = j.program_entries();
    assert_eq!(program.len(), every_kind().len() - 2);
    assert!(program.iter().all(|e| e.branch != META));
    assert_eq!(j.run_start_id().as_deref(), Some("r"));
}

#[test]
fn empty_journal_head_is_genesis() {
    let j = Journal::new(None);
    assert_eq!(j.head(), j.genesis());
    assert_eq!(j.byte_len(), HEADER_LEN as u64);
    assert!(j.verify().is_ok());
    let back = reparse(&j, None);
    assert!(back.is_empty());
}

#[test]
fn record_len_predicts_the_encoding() {
    let mut j = full_journal(None);
    let big = "x".repeat(400);
    j.append(
        ROOT,
        Event::ChannelRecv {
            channel: "c".into(),
            value: big.as_str().into(),
        },
    )
    .unwrap();
    j.append(
        ROOT,
        Event::ChannelRecv {
            channel: "c".into(),
            value: big.as_str().into(),
        },
    )
    .unwrap();
    for e in j.entries() {
        let frame = j.frame_bytes(e.cursor).unwrap();
        let expect = codec::record_len(&e.branch, &e.event, &e.slots) as usize;
        assert_eq!(frame.len(), 4 + expect + 32);
    }
}

#[test]
fn debug_shows_shape_not_content_or_key() {
    let mut j = journal(Some(b"super secret key"));
    j.append(
        ROOT,
        Event::ChannelRecv {
            channel: "c".into(),
            value: "private content".into(),
        },
    )
    .unwrap();
    let shown = format!("{j:?}");
    assert!(!shown.contains("private content"));
    assert!(!shown.contains("super secret key"));
    assert!(shown.contains("keyed: true"));
}

// ---------------------------------------------------------------------------
// Hashing: genesis, skeleton, commitments
// ---------------------------------------------------------------------------

#[test]
fn genesis_is_bound_to_the_flags() {
    let mut data = b"pragmatic/v2/genesis".to_vec();
    data.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(Journal::new(None).genesis(), sha256(&data));
    let mut keyed = b"pragmatic/v2/genesis".to_vec();
    keyed.extend_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        Journal::new(Some(b"k")).genesis(),
        hmac_sha256(b"k", &keyed)
    );
    assert_ne!(sha256(&data), sha256(&keyed));
}

#[test]
fn chain_hashes_the_skeleton_exactly_as_specified() {
    let mut j = journal(None);
    j.append(ROOT, Event::Clock { nanos: 42 }).unwrap();
    j.append(
        ROOT,
        Event::ChannelRecv {
            channel: "c".into(),
            value: "v".into(),
        },
    )
    .unwrap();

    // Clock: kind ‖ at ‖ depth ‖ nfields ‖ (len ‖ nanos) ‖ nslots.
    let mut skel = vec![6u8];
    skel.extend_from_slice(&AT.to_le_bytes());
    skel.push(0);
    skel.push(1);
    skel.extend_from_slice(&8u32.to_le_bytes());
    skel.extend_from_slice(&42u64.to_le_bytes());
    skel.push(0);
    let mut msg = j.genesis().to_vec();
    msg.extend_from_slice(&0u64.to_le_bytes());
    msg.extend_from_slice(&skel);
    assert_eq!(j.entries()[0].hash, sha256(&msg));

    // A slot contributes 0x01 ‖ commitment, never its content.
    let e = &j.entries()[1];
    let mut skel = vec![3u8];
    skel.extend_from_slice(&AT.to_le_bytes());
    skel.extend_from_slice(&[0, 1]);
    skel.extend_from_slice(&1u32.to_le_bytes());
    skel.push(b'c');
    skel.push(1);
    skel.push(0x01);
    skel.extend_from_slice(&e.slots[0].commitment);
    let mut msg = j.entries()[0].hash.to_vec();
    msg.extend_from_slice(&1u64.to_le_bytes());
    msg.extend_from_slice(&skel);
    assert_eq!(e.hash, sha256(&msg));
}

#[test]
fn commitments_follow_the_formula() {
    let mut j = journal(None);
    j.append(
        ROOT,
        Event::ChannelRecv {
            channel: "c".into(),
            value: "content".into(),
        },
    )
    .unwrap();
    let file = j.to_bytes();
    let rec = record(&file, 0);
    // kind, at, depth, nfields, (len, "c"), nslots, state, commitment, salt.
    let slot = 1 + 8 + 1 + 1 + 4 + 1 + 1;
    assert_eq!(rec[slot], 1, "sealed");
    let commitment: [u8; 32] = rec[slot + 1..slot + 33].try_into().unwrap();
    let salt: [u8; SALT_LEN] = rec[slot + 33..slot + 49].try_into().unwrap();
    let mut msg = b"pragmatic/v2/slot".to_vec();
    msg.extend_from_slice(&salt);
    msg.extend_from_slice(&7u64.to_le_bytes());
    msg.extend_from_slice(b"content");
    assert_eq!(commitment, sha256(&msg));
    assert_eq!(j.entries()[0].slots[0].commitment, commitment);
}

#[test]
fn salts_are_fresh_per_slot() {
    let mut j = journal(None);
    for _ in 0..2 {
        j.append(
            ROOT,
            Event::ChannelRecv {
                channel: "c".into(),
                value: "yes".into(),
            },
        )
        .unwrap();
    }
    let a = j.entries()[0].slots[0].commitment;
    let b = j.entries()[1].slots[0].commitment;
    assert_ne!(a, b, "equal short content must not have equal commitments");
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

fn recv(value: &str) -> Event {
    Event::ChannelRecv {
        channel: "c".into(),
        value: value.into(),
    }
}

#[test]
fn large_repeats_become_refs() {
    let message = "m".repeat(DEDUP_MIN_BYTES);
    let mut j = journal(None);
    j.append(
        ROOT,
        Event::DrawIntent {
            provenance: "p".into(),
            parts: vec!["system".into(), message.as_str().into()],
        },
    )
    .unwrap();
    j.append(
        ROOT,
        Event::DrawIntent {
            provenance: "p".into(),
            parts: vec!["system".into(), message.as_str().into(), "next".into()],
        },
    )
    .unwrap();
    let second = &j.entries()[1];
    assert_eq!(second.slots[0].state, SlotState::Sealed, "short: copied");
    assert_eq!(second.slots[1].state, SlotState::Ref);
    assert_eq!(second.slots[1].ref_target, Some((0, 1)));
    assert_eq!(
        second.slots[1].commitment,
        j.entries()[0].slots[1].commitment
    );
    assert_eq!(
        second.event.slot_contents()[1],
        &Content::from(message.as_str())
    );
    let file = j.to_bytes();
    assert_eq!(occurrences(&file, message.as_bytes()), 1);
    let back = reparse(&j, None);
    assert_eq!(back.entries(), j.entries());
    assert!(back.audit().is_ok());
    // A third copy refs the original, never the ref.
    j.append(ROOT, recv(&message)).unwrap();
    assert_eq!(j.entries()[2].slots[0].ref_target, Some((0, 1)));
}

#[test]
fn short_or_different_content_is_copied() {
    let short = "s".repeat(DEDUP_MIN_BYTES - 1);
    let mut j = journal(None);
    j.append(ROOT, recv(&short)).unwrap();
    j.append(ROOT, recv(&short)).unwrap();
    assert_eq!(j.entries()[1].slots[0].state, SlotState::Sealed);
    let a = "a".repeat(300);
    let b = "b".repeat(300);
    j.append(ROOT, recv(&a)).unwrap();
    j.append(ROOT, recv(&b)).unwrap();
    assert_eq!(j.entries()[3].slots[0].state, SlotState::Sealed);
}

#[test]
fn repeats_within_one_record_are_both_sealed() {
    let big = "z".repeat(500);
    let mut j = journal(None);
    j.append(
        ROOT,
        Event::DrawIntent {
            provenance: "p".into(),
            parts: vec![big.as_str().into(), big.as_str().into()],
        },
    )
    .unwrap();
    let e = &j.entries()[0];
    assert!(e.slots.iter().all(|s| s.state == SlotState::Sealed));
    j.append(ROOT, recv(&big)).unwrap();
    assert_eq!(j.entries()[1].slots[0].ref_target, Some((0, 0)));
}

#[test]
fn dedup_index_survives_a_reparse() {
    let big = "q".repeat(1000);
    let mut j = journal(None);
    j.append(ROOT, recv(&big)).unwrap();
    let mut back = reparse(&j, None);
    back.set_clock(fixed_clock);
    back.append(ROOT, recv(&big)).unwrap();
    assert_eq!(back.entries()[1].slots[0].state, SlotState::Ref);
}

// ---------------------------------------------------------------------------
// Canonical decoding (spec 2.4)
// ---------------------------------------------------------------------------

/// A record assembled field by field, so each rule can be broken alone.
#[derive(Clone)]
struct Rec {
    kind: u8,
    branch: Vec<u32>,
    fields: Vec<Vec<u8>>,
    slots: Vec<Vec<u8>>,
    nfields: Option<u8>,
    nslots: Option<u8>,
    depth: Option<u8>,
    trailing: Vec<u8>,
}

impl Rec {
    fn new(kind: u8, fields: Vec<Vec<u8>>, slots: Vec<Vec<u8>>) -> Rec {
        Rec {
            kind,
            branch: if kind == 10 { vec![META_ID] } else { vec![] },
            fields,
            slots,
            nfields: None,
            nslots: None,
            depth: None,
            trailing: vec![],
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut out = vec![self.kind];
        out.extend_from_slice(&AT.to_le_bytes());
        out.push(self.depth.unwrap_or(self.branch.len() as u8));
        for b in &self.branch {
            out.extend_from_slice(&b.to_le_bytes());
        }
        out.push(self.nfields.unwrap_or(self.fields.len() as u8));
        for f in &self.fields {
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(f);
        }
        out.push(self.nslots.unwrap_or(self.slots.len() as u8));
        for s in &self.slots {
            out.extend_from_slice(s);
        }
        out.extend_from_slice(&self.trailing);
        out
    }
}

fn s(text: &str) -> Vec<u8> {
    text.as_bytes().to_vec()
}

fn u64f(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn u32f(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn sealed(content: &[u8]) -> Vec<u8> {
    let salt = [7u8; SALT_LEN];
    let mut out = vec![1u8];
    out.extend_from_slice(&codec::commitment(&salt, content));
    out.extend_from_slice(&salt);
    out.extend_from_slice(&(content.len() as u32).to_le_bytes());
    out.extend_from_slice(content);
    out
}

fn stateful(state: u8, commitment: [u8; 32]) -> Vec<u8> {
    let mut out = vec![state];
    out.extend_from_slice(&commitment);
    out
}

fn ref_slot(commitment: [u8; 32], cursor: u64, slot: u8) -> Vec<u8> {
    let mut out = stateful(4, commitment);
    out.extend_from_slice(&cursor.to_le_bytes());
    out.push(slot);
    out
}

/// A valid record of each kind.
fn valid(kind: u8) -> Rec {
    let p = || sealed(b"payload");
    match kind {
        1 => Rec::new(1, vec![s("model")], vec![p()]),
        2 => Rec::new(2, vec![u64f(0), s(r#"{"outcome":"ok"}"#)], vec![p(), p()]),
        3 => Rec::new(3, vec![s("c")], vec![p()]),
        4 => Rec::new(4, vec![s("tool")], vec![p()]),
        5 => Rec::new(5, vec![u64f(0), s("ok"), s("")], vec![p()]),
        6 => Rec::new(6, vec![u64f(9)], vec![]),
        7 => Rec::new(7, vec![s("agent"), s("h")], vec![]),
        8 => Rec::new(8, vec![u32f(0), u32f(2)], vec![]),
        9 => Rec::new(9, vec![s("patch")], vec![]),
        10 => Rec::new(10, vec![s("attempt.start"), s("{}")], vec![]),
        11 => Rec::new(11, vec![s("uuid4"), s("[]")], vec![p()]),
        12 => Rec::new(12, vec![s("recv"), s("c"), s("Timeout")], vec![]),
        _ => unreachable!(),
    }
}

/// Decode one record the way `Journal::parse` does: structure, context,
/// then re-encode and byte-compare.
fn decode(
    bytes: &[u8],
    cursor: Cursor,
    prior: &[Entry],
    withheld: bool,
) -> Result<Entry, &'static str> {
    let raw = codec::decode_raw(bytes)?;
    let opts = DecodeOpts {
        allow_withheld: withheld,
        probe: false,
    };
    let (entry, salts) = codec::build_entry(&raw, cursor, prior, opts)?;
    let mut again = Vec::new();
    codec::encode_record(&mut again, &entry, &salts);
    if again != bytes {
        return Err("record is not canonically encoded");
    }
    Ok(entry)
}

fn rejects(rec: &Rec, reason: &str) {
    assert_eq!(decode(&rec.bytes(), 0, &[], false).map(|_| ()), Err(reason));
}

#[test]
fn valid_records_of_every_kind_decode() {
    for kind in 1..=12 {
        assert!(
            decode(&valid(kind).bytes(), 0, &[], false).is_ok(),
            "kind {kind}"
        );
    }
}

#[test]
fn record_must_be_consumed_exactly() {
    for kind in 1..=12 {
        let mut r = valid(kind);
        r.trailing = vec![0];
        rejects(&r, "trailing bytes in record");
        let bytes = valid(kind).bytes();
        assert!(decode(&bytes[..bytes.len() - 1], 0, &[], false).is_err());
    }
    assert_eq!(
        decode(&[], 0, &[], false).map(|_| ()),
        Err("record ends early")
    );
}

#[test]
fn unknown_kinds_are_rejected() {
    for kind in [0u8, 13, 99, 255] {
        let mut r = valid(6);
        r.kind = kind;
        rejects(&r, "unknown record kind");
    }
}

#[test]
fn refusals_name_a_step_and_the_fault_it_raises() {
    for (step, name, fault) in [
        ("recv", "inbox", "Timeout"),
        ("recv", "", "Timeout"),
        ("draw", "", "BudgetExhausted"),
        ("effect", "send", "CapabilityDenied"),
    ] {
        let r = Rec::new(12, vec![s(step), s(name), s(fault)], vec![]);
        assert!(decode(&r.bytes(), 0, &[], false).is_ok(), "{step} {fault}");
    }
    rejects(
        &Rec::new(12, vec![s("sleep"), s(""), s("Timeout")], vec![]),
        "refusal of an unknown step",
    );
    for (step, name, fault) in [
        ("recv", "inbox", "BudgetExhausted"),
        ("draw", "model", "BudgetExhausted"),
        ("effect", "send", "Timeout"),
    ] {
        rejects(
            &Rec::new(12, vec![s(step), s(name), s(fault)], vec![]),
            "refusal fault or name does not fit its step",
        );
    }
    let mut j = journal(None);
    let bad = Event::Refusal {
        step: "draw".into(),
        name: String::new(),
        fault: "Timeout".into(),
    };
    assert!(matches!(j.append(ROOT, bad), Err(Fault::Unsupported(_))));
    assert!(j.is_empty());
}

#[test]
fn field_counts_must_match_the_kind() {
    for kind in 1..=12 {
        let r = valid(kind);
        for n in [r.fields.len() as u8 + 1, r.fields.len() as u8 - 1] {
            let mut bad = r.clone();
            bad.nfields = Some(n);
            rejects(&bad, "field count does not match the kind");
        }
    }
}

#[test]
fn slot_counts_must_match_the_kind() {
    let p = || sealed(b"x");
    let cases: Vec<Rec> = vec![
        Rec::new(1, vec![s("m")], vec![]),
        Rec::new(2, vec![u64f(0), s("{}")], vec![p()]),
        Rec::new(2, vec![u64f(0), s("{}")], vec![p(), p(), p()]),
        Rec::new(3, vec![s("c")], vec![]),
        Rec::new(3, vec![s("c")], vec![p(), p()]),
        Rec::new(4, vec![s("t")], vec![]),
        Rec::new(5, vec![u64f(0), s("ok"), s("")], vec![]),
        Rec::new(5, vec![u64f(0), s("failed"), s("E")], vec![p(), p()]),
        Rec::new(5, vec![u64f(0), s("compensated"), s("")], vec![p()]),
        Rec::new(6, vec![u64f(1)], vec![p()]),
        Rec::new(7, vec![s("a"), s("h")], vec![p()]),
        Rec::new(8, vec![u32f(0), u32f(1)], vec![p()]),
        Rec::new(9, vec![s("m")], vec![p()]),
        Rec::new(10, vec![s("k"), s("{}")], vec![p(), p(), p()]),
        Rec::new(11, vec![s("uuid4"), s("[]")], vec![]),
    ];
    for r in cases {
        rejects(&r, "slot count does not match the kind");
    }
    // The boundaries that are allowed.
    let mut many = Rec::new(1, vec![s("m")], vec![]);
    many.slots = (0..255).map(|_| sealed(b"x")).collect();
    assert!(decode(&many.bytes(), 0, &[], false).is_ok());
    let two_payloads = Rec::new(10, vec![s("k"), s("{}")], vec![p(), p()]);
    assert!(decode(&two_payloads.bytes(), 0, &[], false).is_ok());
    let compensated = Rec::new(5, vec![u64f(0), s("compensated"), s("")], vec![]);
    assert!(decode(&compensated.bytes(), 0, &[], false).is_ok());
}

#[test]
fn fixed_width_fields_have_their_width() {
    for bad in [vec![0u8; 7], vec![0u8; 9], vec![]] {
        rejects(
            &Rec::new(6, vec![bad.clone()], vec![]),
            "u64 field is not 8 bytes",
        );
        let r = Rec::new(
            2,
            vec![bad.clone(), s("{}")],
            vec![sealed(b"h"), sealed(b"b")],
        );
        rejects(&r, "u64 field is not 8 bytes");
        let r = Rec::new(5, vec![bad, s("ok"), s("")], vec![sealed(b"r")]);
        rejects(&r, "u64 field is not 8 bytes");
    }
    for bad in [vec![0u8; 3], vec![0u8; 5]] {
        rejects(
            &Rec::new(8, vec![bad.clone(), u32f(1)], vec![]),
            "u32 field is not 4 bytes",
        );
        rejects(
            &Rec::new(8, vec![u32f(0), bad], vec![]),
            "u32 field is not 4 bytes",
        );
    }
}

#[test]
fn text_fields_must_be_utf8() {
    let bad = vec![0xff, 0xfe];
    let cases = [
        Rec::new(1, vec![bad.clone()], vec![sealed(b"x")]),
        Rec::new(3, vec![bad.clone()], vec![sealed(b"x")]),
        Rec::new(4, vec![bad.clone()], vec![sealed(b"x")]),
        Rec::new(
            5,
            vec![u64f(0), s("failed"), bad.clone()],
            vec![sealed(b"x")],
        ),
        Rec::new(7, vec![s("a"), bad.clone()], vec![]),
        Rec::new(9, vec![bad.clone()], vec![]),
        Rec::new(10, vec![bad.clone(), s("{}")], vec![]),
        Rec::new(11, vec![bad, s("[]")], vec![sealed(b"x")]),
    ];
    for r in cases {
        rejects(&r, "text field is not UTF-8");
    }
}

#[test]
fn json_fields_must_be_strict() {
    let deep_ok = format!("{}{}", "[".repeat(64), "]".repeat(64));
    let too_deep = format!("{}{}", "[".repeat(65), "]".repeat(65));
    let bad: Vec<(Vec<u8>, &str)> = vec![
        (s("{\"a\":1,}"), "expected a string key"),
        (s("{'a':1}"), "expected a string key"),
        (s("{\"a\":1,\"a\":2}"), "JSON field has a duplicate key"),
        (
            s("{\"x\":{\"a\":1,\"a\":1}}"),
            "JSON field has a duplicate key",
        ),
        (s(&too_deep), "JSON field is nested deeper than 64"),
        (b"\xef\xbb\xbf{}".to_vec(), "expected a value"),
        (vec![b'"', 0xff, b'"'], "JSON field is not UTF-8"),
        (s("\"\\ud800\""), "unpaired high surrogate"),
        (s("NaN"), "expected a value"),
        (s("01"), "unexpected data after the value"),
        (s(""), "unexpected end of input"),
    ];
    for (json, reason) in bad {
        rejects(&Rec::new(10, vec![s("k"), json.clone()], vec![]), reason);
        let draw = Rec::new(
            2,
            vec![u64f(0), json.clone()],
            vec![sealed(b"h"), sealed(b"b")],
        );
        rejects(&draw, reason);
        rejects(
            &Rec::new(11, vec![s("random"), json], vec![sealed(b"0.5")]),
            reason,
        );
    }
    let ok = Rec::new(10, vec![s("k"), s(&deep_ok)], vec![]);
    assert!(decode(&ok.bytes(), 0, &[], false).is_ok());
    // Whitespace around and inside the document is valid JSON and is kept
    // byte for byte.
    let spaced = Rec::new(10, vec![s("k"), s(" { \"a\" : [1, 2] } ")], vec![]);
    let e = decode(&spaced.bytes(), 0, &[], false).unwrap();
    assert!(matches!(e.event, Event::Note { ref data, .. } if data == " { \"a\" : [1, 2] } "));
}

#[test]
fn effect_outcome_and_fork_fields_are_checked() {
    for bad in ["OK", "fail", "", "compensated "] {
        let r = Rec::new(5, vec![u64f(0), s(bad), s("")], vec![sealed(b"r")]);
        rejects(&r, "unknown effect outcome");
    }
    rejects(
        &Rec::new(8, vec![u32f(0), u32f(0)], vec![]),
        "fork has no children",
    );
}

#[test]
fn slot_states_are_checked() {
    for state in [0u8, 5, 9, 255] {
        rejects(
            &Rec::new(3, vec![s("c")], vec![stateful(state, [1; 32])]),
            "unknown slot state",
        );
    }
    // Withheld is valid only inside an evidence bundle.
    let withheld = Rec::new(3, vec![s("c")], vec![stateful(3, [1; 32])]);
    rejects(&withheld, "withheld slot in a stored journal");
    let e = decode(&withheld.bytes(), 0, &[], true).unwrap();
    assert_eq!(e.slots[0].state, SlotState::Withheld);
    assert_eq!(e.event.slot_contents()[0], &Content::Withheld);
    // Erased carries only its commitment.
    let erased = Rec::new(3, vec![s("c")], vec![stateful(2, [1; 32])]);
    let e = decode(&erased.bytes(), 0, &[], false).unwrap();
    assert_eq!(e.event.slot_contents()[0], &Content::Erased);
}

#[test]
fn slot_lengths_are_bounded() {
    let mut slot = vec![1u8];
    slot.extend_from_slice(&[0u8; 32 + SALT_LEN]);
    slot.extend_from_slice(&100u32.to_le_bytes());
    slot.extend_from_slice(b"short");
    rejects(
        &Rec::new(3, vec![s("c")], vec![slot]),
        "slot length exceeds the record",
    );
    let mut huge = vec![1u8];
    huge.extend_from_slice(&[0u8; 32 + SALT_LEN]);
    huge.extend_from_slice(&((MAX_SLOT_BYTES + 1) as u32).to_le_bytes());
    rejects(
        &Rec::new(3, vec![s("c")], vec![huge]),
        "slot exceeds the 64 MiB limit",
    );
    // A field length past the end of the record.
    let mut r = valid(9).bytes();
    let len_at = 1 + 8 + 1 + 1;
    r[len_at..len_at + 4].copy_from_slice(&1000u32.to_le_bytes());
    assert_eq!(
        decode(&r, 0, &[], false).map(|_| ()),
        Err("field length exceeds the record")
    );
}

#[test]
fn branch_rules() {
    let mut deep = valid(6);
    deep.branch = vec![1; 33];
    rejects(&deep, "branch deeper than 32");
    deep.branch = vec![1; 32];
    assert!(decode(&deep.bytes(), 0, &[], false).is_ok());
    let mut lying = valid(6);
    lying.depth = Some(40);
    rejects(&lying, "branch deeper than 32");

    let mut note_on_root = valid(10);
    note_on_root.branch = vec![];
    rejects(
        &note_on_root,
        "only notes may be on the meta branch, and notes must be",
    );
    let mut note_below_meta = valid(10);
    note_below_meta.branch = vec![META_ID, 0];
    rejects(
        &note_below_meta,
        "only notes may be on the meta branch, and notes must be",
    );
    let mut clock_on_meta = valid(6);
    clock_on_meta.branch = vec![META_ID];
    rejects(
        &clock_on_meta,
        "only notes may be on the meta branch, and notes must be",
    );
}

#[test]
fn ref_rules() {
    // Entry 0 holds a sealed slot, entry 1 an erased one, entry 2 a ref.
    let target = decode(&valid(3).bytes(), 0, &[], false).unwrap();
    let c0 = target.slots[0].commitment;
    let erased = decode(
        &Rec::new(3, vec![s("c")], vec![stateful(2, [9; 32])]).bytes(),
        1,
        std::slice::from_ref(&target),
        false,
    )
    .unwrap();
    let ok_ref = Rec::new(3, vec![s("c")], vec![ref_slot(c0, 0, 0)]);
    let prior = vec![target.clone(), erased.clone()];
    let e = decode(&ok_ref.bytes(), 2, &prior, false).unwrap();
    assert_eq!(e.slots[0].state, SlotState::Ref);
    assert_eq!(e.slots[0].ref_target, Some((0, 0)));
    assert_eq!(e.event.slot_contents()[0], target.event.slot_contents()[0]);
    // To an erased target: valid, and reads as erased.
    let to_erased = Rec::new(3, vec![s("c")], vec![ref_slot([9; 32], 1, 0)]);
    let e = decode(&to_erased.bytes(), 2, &prior, false).unwrap();
    assert_eq!(e.event.slot_contents()[0], &Content::Erased);
    let mut prior3 = prior.clone();
    prior3.push(e);

    let cases: Vec<(Vec<u8>, Cursor, &str)> = vec![
        (
            ref_slot(c0, 3, 0),
            3,
            "ref does not point to an earlier entry",
        ),
        (
            ref_slot(c0, 7, 0),
            3,
            "ref does not point to an earlier entry",
        ),
        (ref_slot(c0, 0, 1), 3, "ref target slot does not exist"),
        (ref_slot([9; 32], 2, 0), 3, "ref points to another ref"),
        (
            ref_slot([5; 32], 0, 0),
            3,
            "ref commitment differs from its target",
        ),
    ];
    for (slot, cursor, reason) in cases {
        let r = Rec::new(3, vec![s("c")], vec![slot]);
        assert_eq!(
            decode(&r.bytes(), cursor, &prior3, false).map(|_| ()),
            Err(reason)
        );
    }
    // A ref to a slot with no entry is missing (outside a probe).
    let r = Rec::new(3, vec![s("c")], vec![ref_slot(c0, 0, 0)]);
    assert_eq!(
        decode(&r.bytes(), 1, &[], false).map(|_| ()),
        Err("ref target entry is missing")
    );

    // Withheld targets: only inside a bundle.
    let withheld = decode(
        &Rec::new(3, vec![s("c")], vec![stateful(3, [4; 32])]).bytes(),
        0,
        &[],
        true,
    )
    .unwrap();
    let to_withheld = Rec::new(3, vec![s("c")], vec![ref_slot([4; 32], 0, 0)]);
    let bundle = decode(
        &to_withheld.bytes(),
        1,
        std::slice::from_ref(&withheld),
        true,
    )
    .unwrap();
    assert_eq!(bundle.event.slot_contents()[0], &Content::Withheld);
    assert_eq!(
        decode(&to_withheld.bytes(), 1, &[withheld], false).map(|_| ()),
        Err("ref target is withheld")
    );
}

#[test]
fn decoding_failures_mid_file_are_corruption_and_at_the_end_are_torn() {
    let base = full_journal(None).to_bytes();
    let n = frames(&base).len();
    type Breaker = fn(Vec<u8>) -> Vec<u8>;
    let breakers: Vec<(&str, Breaker)> = vec![
        ("trailing byte", |mut r| {
            r.push(0);
            r
        }),
        ("unknown kind", |mut r| {
            r[0] = 200;
            r
        }),
        ("depth 33", |mut r| {
            r[9] = 33;
            r
        }),
        ("truncated", |mut r| {
            r.pop();
            r
        }),
    ];
    for (what, breaker) in breakers {
        for cursor in [1usize, n / 2] {
            let file = replace_record(&base, cursor, &breaker(record(&base, cursor)));
            let (at, _) = corrupt_at(Journal::parse(&file, None));
            assert_eq!(at, cursor as u64, "{what} at {cursor}");
        }
        let last = replace_record(&base, n - 1, &breaker(record(&base, n - 1)));
        let parsed = Journal::parse(&last, None).unwrap();
        assert_eq!(parsed.journal.len(), n as u64 - 1, "{what} at the end");
        assert!(parsed.tail_len > 0);
    }
}

#[test]
fn a_record_that_decodes_but_is_not_canonical_never_reaches_the_chain() {
    // The format has a single encoding for every value, so the byte-compare
    // is defense in depth. Check the property it relies on: re-encoding a
    // decoded record of every kind reproduces it exactly, refs included.
    let message = "m".repeat(400);
    let mut j = full_journal(None);
    j.append(ROOT, recv(&message)).unwrap();
    j.append(ROOT, recv(&message)).unwrap();
    let file = j.to_bytes();
    for (cursor, _) in frames(&file).iter().enumerate() {
        let rec = record(&file, cursor);
        let e = decode(&rec, cursor as u64, &j.entries()[..cursor], false).unwrap();
        assert_eq!(&e.event, &j.entries()[cursor].event);
    }
}

// ---------------------------------------------------------------------------
// Keying and the header (spec 2.1)
// ---------------------------------------------------------------------------

#[test]
fn header_rules() {
    let unkeyed = full_journal(None).to_bytes();
    let keyed = full_journal(Some(b"k")).to_bytes();
    assert!(matches!(
        Journal::parse(&unkeyed, Some(b"k")),
        Err(JournalError::InvalidData(m)) if m.contains("unkeyed but a key was supplied")
    ));
    assert!(matches!(
        Journal::parse(&keyed, None),
        Err(JournalError::Unsupported(_))
    ));
    for bit in [2u32, 3, 4, 1 << 31] {
        let mut bad = unkeyed.clone();
        bad[12..16].copy_from_slice(&bit.to_le_bytes());
        assert!(matches!(
            Journal::parse(&bad, None),
            Err(JournalError::InvalidData(m)) if m.contains("reserved flag bits")
        ));
    }
    assert!(matches!(
        Journal::parse(b"NOTAJRNL\x02\0\0\0\0\0\0\0", None),
        Err(JournalError::InvalidData(_))
    ));
    assert!(matches!(
        Journal::parse(b"", None),
        Err(JournalError::InvalidData(_))
    ));
    assert!(matches!(
        Journal::parse(&unkeyed[..14], None),
        Err(JournalError::InvalidData(_))
    ));
    let mut v3 = unkeyed.clone();
    v3[8] = 3;
    assert!(
        matches!(Journal::parse(&v3, None), Err(JournalError::InvalidData(m)) if m.contains("format 3"))
    );
    // Faults: keyed-without-key is Unsupported, the rest are I/O errors.
    assert!(matches!(
        Fault::from(Journal::parse(&keyed, None).unwrap_err()),
        Fault::Unsupported(_)
    ));
    assert_eq!(
        std::io::Error::from(Journal::parse(&unkeyed, Some(b"k")).unwrap_err()).kind(),
        std::io::ErrorKind::InvalidData
    );
}

#[test]
fn clearing_the_keyed_bit_is_detected_never_truncated() {
    for entries in [1usize, every_kind().len()] {
        let mut j = journal(Some(b"k"));
        for (b, e) in every_kind().into_iter().take(entries) {
            j.append(&b, e).unwrap();
        }
        let mut downgraded = j.to_bytes();
        downgraded[12] = 0;
        // Read as unkeyed: the genesis differs, so the very first link fails,
        // and an intact frame failing its link is corruption, not a crash.
        let (cursor, reason) = corrupt_at(Journal::parse(&downgraded, None));
        assert_eq!(cursor, 0);
        assert!(reason.contains("chain link"), "{reason}");
        // With the key, the reader refuses the unkeyed header outright.
        assert!(matches!(
            Journal::parse(&downgraded, Some(b"k")),
            Err(JournalError::InvalidData(_))
        ));
    }
}

#[test]
fn rechaining_as_unkeyed_cannot_fool_a_keyed_reader() {
    let keyed = full_journal(Some(b"k"));
    // An attacker without the key rebuilds the same entries as an unkeyed
    // journal (valid on its own terms).
    let mut forged = journal(None);
    for e in keyed.entries() {
        forged.append_at(e.at, &e.branch, e.event.clone()).unwrap();
    }
    let bytes = forged.to_bytes();
    assert!(Journal::parse(&bytes, None).is_ok());
    assert!(matches!(
        Journal::parse(&bytes, Some(b"k")),
        Err(JournalError::InvalidData(_))
    ));
}

#[test]
fn wrong_key_and_forged_keyed_bit_are_corruption_at_zero() {
    let keyed = full_journal(Some(b"right")).to_bytes();
    assert_eq!(corrupt_at(Journal::parse(&keyed, Some(b"wrong"))).0, 0);
    let mut upgraded = full_journal(None).to_bytes();
    upgraded[12] = 1;
    assert!(matches!(
        Journal::parse(&upgraded, None),
        Err(JournalError::Unsupported(_))
    ));
    assert_eq!(corrupt_at(Journal::parse(&upgraded, Some(b"any"))).0, 0);
}

// ---------------------------------------------------------------------------
// Torn tails versus corruption (spec 2.14)
// ---------------------------------------------------------------------------

#[test]
fn every_cut_inside_the_last_frame_is_a_torn_tail() {
    let file = full_journal(None).to_bytes();
    let all = frames(&file);
    let (last_start, _) = *all.last().unwrap();
    for cut in last_start + 1..file.len() {
        let parsed = Journal::parse(&file[..cut], None).unwrap();
        assert_eq!(parsed.journal.len(), all.len() as u64 - 1, "cut at {cut}");
        assert_eq!(parsed.valid_len, last_start as u64);
        assert_eq!(parsed.tail_len, (cut - last_start) as u64);
        assert_eq!(parsed.journal.torn_bytes(), parsed.tail_len);
        assert_eq!(parsed.journal.audit().torn_bytes, parsed.tail_len);
        assert!(parsed.journal.audit().is_ok());
    }
    // Cutting exactly at a frame boundary is a clean, shorter journal.
    let parsed = Journal::parse(&file[..last_start], None).unwrap();
    assert_eq!(parsed.tail_len, 0);
}

#[test]
fn zero_filled_tails_are_torn() {
    let file = full_journal(None).to_bytes();
    let n = frames(&file).len() as u64;
    for zeros in [1usize, 3, 4, 35, 36, 47, 48, 100, 4096] {
        let mut padded = file.clone();
        padded.resize(file.len() + zeros, 0);
        let parsed = Journal::parse(&padded, None).unwrap();
        assert_eq!((parsed.journal.len(), parsed.tail_len), (n, zeros as u64));
    }
    // A partial frame followed by zeros (the filesystem extended the file
    // before the data reached it).
    let (last_start, _) = *frames(&file).last().unwrap();
    let mut partial = file[..last_start + 30].to_vec();
    partial.resize(partial.len() + 8192, 0);
    let parsed = Journal::parse(&partial, None).unwrap();
    assert_eq!(parsed.journal.len(), n - 1);
    // The last frame's record intact but its hash never written.
    let mut unwritten = file.clone();
    let end = unwritten.len();
    unwritten[end - 32..].fill(0);
    let parsed = Journal::parse(&unwritten, None).unwrap();
    assert_eq!(
        (parsed.journal.len(), parsed.tail_len),
        (n - 1, (end - last_start) as u64)
    );
}

#[test]
fn garbage_after_the_last_frame_is_torn() {
    let file = full_journal(None).to_bytes();
    let n = frames(&file).len() as u64;
    let mut x: u32 = 0x1234_5678;
    let mut noisy = file.clone();
    for _ in 0..5000 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        noisy.push(x as u8);
    }
    let parsed = Journal::parse(&noisy, None).unwrap();
    assert_eq!((parsed.journal.len(), parsed.tail_len), (n, 5000));
}

#[test]
fn every_length_bit_flip_mid_file_is_corruption() {
    let file = full_journal(None).to_bytes();
    let all = frames(&file);
    for cursor in [1usize, 4, all.len() - 2] {
        let (start, _) = all[cursor];
        for bit in 0..32 {
            let mut bad = file.clone();
            bad[start + bit / 8] ^= 1 << (bit % 8);
            let (at, _) = corrupt_at(Journal::parse(&bad, None));
            assert_eq!(at, cursor as u64, "bit {bit} of frame {cursor}");
        }
    }
}

#[test]
fn content_and_hash_bit_flips_mid_file_are_corruption() {
    let file = full_journal(None).to_bytes();
    let all = frames(&file);
    // Cursor 1 is a draw intent: flip a byte of its last part's content.
    let (start, len) = all[1];
    let mut content_flip = file.clone();
    content_flip[start + 4 + len - 1] ^= 0x01;
    let (at, reason) = corrupt_at(Journal::parse(&content_flip, None));
    assert_eq!(at, 1);
    assert!(reason.contains("commitment"), "{reason}");
    // A flip in a stored hash: the successor still chains from the true
    // hash, so this is corruption too.
    for cursor in [1usize, 5] {
        let (start, len) = all[cursor];
        let mut hash_flip = file.clone();
        hash_flip[start + 4 + len + 3] ^= 0x80;
        assert_eq!(
            corrupt_at(Journal::parse(&hash_flip, None)).0,
            cursor as u64
        );
    }
    // A flip in a field changes the skeleton, so the link fails.
    let (start, _) = all[8];
    let mut field_flip = file.clone();
    field_flip[start + 4 + 1] ^= 0x01; // `at`
    assert_eq!(corrupt_at(Journal::parse(&field_flip, None)).0, 8);
}

#[test]
fn damage_to_the_last_frame() {
    let mut j = full_journal(None);
    j.append(ROOT, recv("the last content")).unwrap();
    let file = j.to_bytes();
    let all = frames(&file);
    let n = all.len() as u64;
    let (start, len) = *all.last().unwrap();
    // A flipped content byte in a frame whose hash still verifies: the
    // writer wrote the whole frame, so the content was damaged afterwards
    // (bit rot, tampering). Corruption, never a tail a writer may cut off.
    let mut content = file.clone();
    content[start + 4 + len - 1] ^= 0x01;
    let (at, reason) = corrupt_at(Journal::parse(&content, None));
    assert_eq!(at, n - 1);
    assert!(reason.contains("commitment"), "{reason}");
    // The same content reading back as zeros, the way a block the
    // filesystem extended but never wrote does when a crash kept the
    // block with the hash: a torn tail.
    let body = "the last content".len();
    let mut unwritten = file.clone();
    unwritten[start + 4 + len - body..start + 4 + len].fill(0);
    let parsed = Journal::parse(&unwritten, None).unwrap();
    assert_eq!(
        (parsed.journal.len(), parsed.tail_len),
        (n - 1, (len + 36) as u64)
    );
    // An intact frame whose link fails is not something a crash leaves
    // behind: a changed field, or a changed stored hash, is corruption.
    let mut field = file.clone();
    field[start + 4 + 1] ^= 0x01;
    assert_eq!(corrupt_at(Journal::parse(&field, None)).0, n - 1);
    let mut hash = file.clone();
    hash[start + 4 + len] ^= 0x01;
    assert_eq!(corrupt_at(Journal::parse(&hash, None)).0, n - 1);
}

#[test]
fn oversized_frame_length_is_never_read_as_a_record() {
    let file = full_journal(None).to_bytes();
    let n = frames(&file).len() as u64;
    let mut huge = file.clone();
    huge.extend_from_slice(&((MAX_RECORD_BYTES + 1) as u32).to_le_bytes());
    huge.extend_from_slice(&[0u8; 64]);
    let parsed = Journal::parse(&huge, None).unwrap();
    assert_eq!((parsed.journal.len(), parsed.tail_len), (n, 68));
    // Mid-file, the same length is corruption.
    let (start, _) = frames(&file)[2];
    let mut mid = file.clone();
    mid[start..start + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(corrupt_at(Journal::parse(&mid, None)).0, 2);
}

#[test]
fn parsing_is_pure_and_repeatable() {
    let mut file = full_journal(None).to_bytes();
    file.extend_from_slice(&[1, 2, 3]);
    let copy = file.clone();
    let a = Journal::parse(&file, None).unwrap();
    let b = Journal::parse(&file, None).unwrap();
    assert_eq!(file, copy);
    assert_eq!(a.journal.entries(), b.journal.entries());
    assert_eq!((a.valid_len, a.tail_len), (b.valid_len, b.tail_len));
}

#[test]
fn a_parsed_journal_continues_from_its_valid_prefix() {
    let mut file = full_journal(None).to_bytes();
    let clean_len = file.len();
    file.extend_from_slice(&[5, 0, 0]);
    let mut j = Journal::parse(&file, None).unwrap().journal;
    assert_eq!(j.byte_len(), clean_len as u64);
    assert!(j.pending().is_none());
    j.append(ROOT, Event::Clock { nanos: 1 }).unwrap();
    let (at, frames, _) = j.pending().unwrap();
    let mut extended = file[..clean_len].to_vec();
    extended.extend_from_slice(frames);
    assert_eq!(at, every_kind().len() as u64);
    assert_eq!(
        Journal::parse(&extended, None).unwrap().journal.len(),
        at + 1
    );
}

// ---------------------------------------------------------------------------
// verify() and tampering
// ---------------------------------------------------------------------------

#[test]
fn verify_finds_the_first_bad_cursor() {
    let base = full_journal(None);
    let mut j = base.clone();
    j.tamper(1, |e| {
        if let Event::DrawIntent { parts, .. } = &mut e.event {
            parts[1] = "forged".into();
        }
    });
    assert_eq!(j.verify(), Err(1));
    assert_eq!(j.audit().first_bad, Some(1));

    let mut j = base.clone();
    j.tamper(3, |e| {
        if let Event::ChannelRecv { channel, .. } = &mut e.event {
            *channel = "other".into();
        }
    });
    assert_eq!(j.verify(), Err(3));

    let mut j = base.clone();
    j.tamper(8, |e| e.at += 1);
    assert_eq!(j.verify(), Err(8));

    let mut j = base.clone();
    j.tamper(2, |e| e.slots[0].state = SlotState::Erased);
    assert_eq!(j.verify(), Err(2));

    // Refs must resolve to their target's content.
    let big = "r".repeat(300);
    let mut j = journal(None);
    j.append(ROOT, recv(&big)).unwrap();
    j.append(ROOT, recv(&big)).unwrap();
    assert!(j.verify().is_ok());
    j.tamper(1, |e| {
        if let Event::ChannelRecv { value, .. } = &mut e.event {
            *value = "different".into();
        }
    });
    assert_eq!(j.verify(), Err(1));
}

#[test]
fn truncate_hook_models_a_durable_prefix() {
    let mut j = full_journal(None);
    j.mark_persisted(3);
    j.truncate(5);
    assert_eq!(j.len(), 5);
    let (at, frames, _) = j.pending().unwrap();
    assert_eq!(at, 3);
    let mut file = header(0).to_vec();
    for c in 0..3 {
        file.extend_from_slice(&j.frame_bytes(c).unwrap());
    }
    file.extend_from_slice(frames);
    assert_eq!(file, j.to_bytes());
    assert_eq!(j.byte_len(), file.len() as u64);
    assert!(reparse(&j, None).verify().is_ok());
}

// ---------------------------------------------------------------------------
// Appending: validation, limits, server-only notes
// ---------------------------------------------------------------------------

fn unsupported(r: Result<Cursor, Fault>) -> String {
    match r {
        Err(Fault::Unsupported(m)) => m,
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn append_refuses_what_a_reader_would_reject() {
    let mut j = journal(None);
    let cases: Vec<(Vec<u32>, Event, &str)> = vec![
        (
            vec![],
            Event::Note {
                kind: "x".into(),
                data: "{}".into(),
                payload: vec![],
            },
            "meta branch",
        ),
        (META.to_vec(), Event::Clock { nanos: 1 }, "meta branch"),
        (vec![0; 33], Event::Clock { nanos: 1 }, "deeper than 32"),
        (
            vec![],
            Event::DrawIntent {
                provenance: "p".into(),
                parts: vec![],
            },
            "request part",
        ),
        (
            vec![],
            Event::DrawIntent {
                provenance: "p".into(),
                parts: (0..256).map(|_| "x".into()).collect(),
            },
            "255 slots",
        ),
        (
            vec![],
            Event::DrawResult {
                intent: 0,
                meta: "{\"a\":1,\"a\":2}".into(),
                head: "h".into(),
                body: "b".into(),
            },
            "strict JSON",
        ),
        (
            META.to_vec(),
            Event::Note {
                kind: "k".into(),
                data: "not json".into(),
                payload: vec![],
            },
            "strict JSON",
        ),
        (
            META.to_vec(),
            Event::Note {
                kind: "k".into(),
                data: "{}".into(),
                payload: vec!["a".into(), "b".into(), "c".into()],
            },
            "two payload",
        ),
        (
            vec![],
            Event::Random {
                source: "randint".into(),
                args: "[1,".into(),
                value: "1".into(),
            },
            "strict JSON",
        ),
        (
            vec![],
            Event::ChannelRecv {
                channel: "c".into(),
                value: Content::Erased,
            },
            "sealed",
        ),
        (
            vec![],
            Event::ChannelRecv {
                channel: "c".into(),
                value: Content::Withheld,
            },
            "sealed",
        ),
        (
            vec![],
            Event::EffectResult {
                intent: 0,
                outcome: EffectOutcome::Ok,
                error_kind: String::new(),
                payload: None,
            },
            "payload",
        ),
        (
            vec![],
            Event::EffectResult {
                intent: 0,
                outcome: EffectOutcome::Compensated,
                error_kind: String::new(),
                payload: Some("x".into()),
            },
            "payload",
        ),
        (
            vec![],
            Event::Fork {
                base: 0,
                children: 0,
            },
            "at least one child",
        ),
        (
            vec![],
            Event::Fork {
                base: u32::MAX - 1,
                children: 2,
            },
            "0xFFFF_FFFF",
        ),
        (
            vec![],
            Event::Legacy(LegacyEvent::Clock { nanos: 1 }),
            "format 1",
        ),
    ];
    for (branch, event, needle) in cases {
        let m = unsupported(j.append(&branch, event));
        assert!(m.contains(needle), "{m} lacks {needle}");
    }
    assert!(j.is_empty());
    // The largest fork that numbers every child below 0xFFFF_FFFF.
    j.append(
        ROOT,
        Event::Fork {
            base: u32::MAX - 2,
            children: 2,
        },
    )
    .unwrap();
}

#[test]
fn a_failed_append_changes_nothing() {
    let mut j = full_journal(None);
    let before = (j.len(), j.head(), j.byte_len(), j.to_bytes());
    let _ = j.append(
        ROOT,
        Event::Fork {
            base: 0,
            children: 0,
        },
    );
    let _ = j.append(
        ROOT,
        Event::ChannelRecv {
            channel: "c".into(),
            value: Content::Erased,
        },
    );
    assert_eq!(before, (j.len(), j.head(), j.byte_len(), j.to_bytes()));
}

#[test]
fn server_only_notes_are_refused_by_append() {
    let mut j = journal(None);
    for kind in note::SERVER_ONLY {
        let m = unsupported(j.append(
            META,
            Event::Note {
                kind: kind.into(),
                data: "{}".into(),
                payload: vec![],
            },
        ));
        assert!(m.contains(kind));
    }
    assert!(j.is_empty());
    // The privileged path takes exactly those kinds.
    assert!(j
        .append_server_note(AT, note::RUN_START, "{}", vec![])
        .is_err());
    let c = j
        .append_server_note(AT, note::CUSTODY, r#"{"requests":3}"#, vec![])
        .unwrap();
    assert_eq!(j.get(c).unwrap().event.note_kind(), Some(note::CUSTODY));
    assert!(reparse(&j, None).audit().is_ok());
}

#[test]
fn torn_tail_note_records_the_move() {
    let mut j = journal(None);
    let torn = TornTail {
        offset: 1234,
        bytes: 56,
        sha256: sha256(b"tail"),
        moved_to: "abc.torn-1".into(),
        at_cursor: 0,
    };
    j.append_torn_tail(AT, &torn).unwrap();
    let Event::Note {
        kind,
        data,
        payload,
    } = &j.entries()[0].event
    else {
        panic!("not a note");
    };
    assert_eq!(kind, note::TORN_TAIL);
    assert!(payload.is_empty());
    assert_eq!(
        data,
        &format!(
            r#"{{"bytes":56,"moved_to":"abc.torn-1","offset":1234,"sha256":"{}"}}"#,
            crate::sha256::hex(&sha256(b"tail"))
        )
    );
}

#[test]
fn slot_over_64_mib_is_too_large() {
    let mut j = journal(None);
    let big = vec![b'x'; MAX_SLOT_BYTES as usize + 1];
    let r = j.append(
        ROOT,
        Event::ChannelRecv {
            channel: "c".into(),
            value: Content::from(big),
        },
    );
    assert_eq!(
        r,
        Err(Fault::TooLarge {
            size: MAX_SLOT_BYTES + 1,
            limit: MAX_SLOT_BYTES
        })
    );
    assert!(j.is_empty());
}

#[test]
fn record_over_256_mib_is_too_large() {
    // Fields count toward the record too; a long field is the cheapest way
    // to build an oversized record without hashing slot content.
    let mut j = journal(None);
    let provenance = "p".repeat(MAX_RECORD_BYTES as usize);
    match j.append(
        ROOT,
        Event::DrawIntent {
            provenance,
            parts: vec!["x".into()],
        },
    ) {
        Err(Fault::TooLarge { size, limit }) => {
            assert_eq!(limit, MAX_RECORD_BYTES);
            assert!(size > MAX_RECORD_BYTES);
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
    assert!(j.is_empty());
}

#[test]
fn run_id_rules() {
    let long = "a".repeat(MAX_RUN_ID_LEN);
    for ok in [
        "r",
        "run-1",
        "a.b_c:d-E9",
        long.as_str(),
        "pragmatic",
        "x:pragmatic:",
    ] {
        assert!(validate_run_id(ok).is_ok(), "{ok}");
    }
    let too_long = "a".repeat(MAX_RUN_ID_LEN + 1);
    for bad in [
        "",
        too_long.as_str(),
        "has space",
        "a/b",
        "../x",
        "é",
        "tab\t",
        "pragmatic:x",
    ] {
        assert!(
            matches!(validate_run_id(bad), Err(Fault::Unsupported(_))),
            "{bad:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Erasure (spec 2.13)
// ---------------------------------------------------------------------------

const SSN: &str = "078-05-1120";

/// run.start, a draw whose second part is a large personal message, its
/// result, a repeat of the message (a ref), and an unrelated receive.
fn personal_journal() -> (Journal, String) {
    let message = format!(
        "{{\"role\":\"user\",\"content\":\"my ssn is {SSN}\"}}{}",
        " ".repeat(300)
    );
    let mut j = journal(None);
    j.append(
        META,
        Event::Note {
            kind: note::RUN_START.into(),
            data: r#"{"run_id":"r"}"#.into(),
            payload: vec![],
        },
    )
    .unwrap();
    j.append(
        ROOT,
        Event::DrawIntent {
            provenance: "p".into(),
            parts: vec!["POST /v1/messages".into(), message.as_str().into()],
        },
    )
    .unwrap();
    j.append(
        ROOT,
        Event::DrawResult {
            intent: 1,
            meta: r#"{"outcome":"ok"}"#.into(),
            head: "{}".into(),
            body: format!("noted: {SSN}").into(),
        },
    )
    .unwrap();
    j.append(
        ROOT,
        Event::DrawIntent {
            provenance: "p".into(),
            parts: vec![
                "POST /v1/messages".into(),
                message.as_str().into(),
                "more".into(),
            ],
        },
    )
    .unwrap();
    j.append(ROOT, recv("unrelated")).unwrap();
    j.mark_persisted(j.len());
    (j, message)
}

fn note_data(j: &Journal, cursor: Cursor) -> crate::json::Json {
    match &j.get(cursor).unwrap().event {
        Event::Note { data, .. } => crate::json::parse(data).unwrap(),
        _ => panic!("not a note"),
    }
}

#[test]
fn erasure_keeps_every_hash_and_accounts_for_itself() {
    let (j, message) = personal_journal();
    assert_eq!(j.entries()[3].slots[1].state, SlotState::Ref);
    let note = ErasureNote {
        by: "tok_123".into(),
        authenticated: true,
        reason_code: "dsar".into(),
        access_log_cursor: Some(77),
        reason: "subject request".into(),
    };
    let e = j
        .erase(&EraseSelector::Slots(vec![(1, 1)]), &note, AT)
        .unwrap();
    assert_eq!(e.slots, vec![(1, 1)]);
    assert_eq!(e.note_cursor, j.len());
    let n = &e.journal;
    assert_eq!(n.len(), j.len() + 1);
    for (o, x) in j.entries().iter().zip(n.entries()) {
        assert_eq!(o.hash, x.hash);
        for (os, xs) in o.slots.iter().zip(&x.slots) {
            assert_eq!(os.commitment, xs.commitment);
        }
    }
    assert_eq!(n.entries()[1].slots[1].state, SlotState::Erased);
    assert_eq!(n.entries()[1].event.slot_contents()[1], &Content::Erased);
    // The ref stays a ref and reads as erased through its target.
    assert_eq!(n.entries()[3].slots[1].state, SlotState::Ref);
    assert_eq!(n.entries()[3].event.slot_contents()[1], &Content::Erased);
    assert_eq!(occurrences(&e.file, message.as_bytes()), 0);
    assert_eq!(e.file, n.to_bytes());
    assert!(n.verify().is_ok());
    assert!(n.audit().is_ok(), "{:?}", n.audit());

    let last = n.entries().last().unwrap();
    assert_eq!(last.branch, META);
    let Event::Note {
        kind,
        data,
        payload,
    } = &last.event
    else {
        panic!("not a note")
    };
    assert_eq!(kind, note::ERASURE);
    assert_eq!(
        data,
        r#"{"access_log_cursor":77,"authenticated":true,"by":"tok_123","reason_code":"dsar","slots":[[1,1]]}"#
    );
    assert_eq!(payload, &vec![Content::from("subject request")]);
}

#[test]
fn erasure_by_match_covers_every_copy() {
    let (j, message) = personal_journal();
    let e = j
        .erase(
            &EraseSelector::Match(SSN.as_bytes().to_vec()),
            &ErasureNote::local("dsar", ""),
            AT,
        )
        .unwrap();
    // The message (once, deduplicated) and the response body.
    assert_eq!(e.slots, vec![(1, 1), (2, 1)]);
    assert_eq!(occurrences(&e.file, SSN.as_bytes()), 0);
    assert_eq!(occurrences(&e.file, message.as_bytes()), 0);
    let n = &e.journal;
    assert!(n.audit().is_ok());
    assert!(n.entries()[4].event.slot_contents()[0].is_sealed());
    // No reason: no payload slot.
    let Event::Note { payload, .. } = &n.entries().last().unwrap().event else {
        panic!()
    };
    assert!(payload.is_empty());
    let data = note_data(n, e.note_cursor);
    assert_eq!(data.get("authenticated").unwrap().as_bool(), Some(false));
    assert!(data
        .get("by")
        .unwrap()
        .as_str()
        .unwrap()
        .starts_with("local:"));
    assert!(data.get("access_log_cursor").unwrap().is_null());
}

#[test]
fn naming_a_ref_erases_its_target() {
    let (j, _) = personal_journal();
    let e = j
        .erase(
            &EraseSelector::Slots(vec![(3, 1)]),
            &ErasureNote::local("dsar", ""),
            AT,
        )
        .unwrap();
    assert_eq!(e.slots, vec![(1, 1)]);
    assert_eq!(
        e.journal.entries()[1].event.slot_contents()[1],
        &Content::Erased
    );
    assert_eq!(
        e.journal.entries()[3].event.slot_contents()[1],
        &Content::Erased
    );
}

#[test]
fn erase_all_and_then_continue() {
    let (j, _) = personal_journal();
    let e = j
        .erase(
            &EraseSelector::All,
            &ErasureNote::local("retention", ""),
            AT,
        )
        .unwrap();
    let sealed_before = j
        .entries()
        .iter()
        .flat_map(|x| &x.slots)
        .filter(|s| s.state == SlotState::Sealed)
        .count();
    assert_eq!(e.slots.len(), sealed_before);
    let mut n = e.journal;
    assert!(n.audit().is_ok());
    // Nothing left to erase, and repeating is an explicit error.
    assert!(matches!(
        n.erase(&EraseSelector::All, &ErasureNote::local("again", ""), AT),
        Err(Fault::Unsupported(m)) if m.contains("nothing to erase")
    ));
    assert!(matches!(
        n.erase(
            &EraseSelector::Slots(vec![(1, 1)]),
            &ErasureNote::local("again", ""),
            AT
        ),
        Err(Fault::Unsupported(_))
    ));
    // The chain continues on the erased journal; the same content is sealed
    // afresh rather than referring to erased bytes.
    let (_, message) = personal_journal();
    n.append(ROOT, recv(&message)).unwrap();
    assert_eq!(
        n.entries().last().unwrap().slots[0].state,
        SlotState::Sealed
    );
    assert!(reparse(&n, None).audit().is_ok());
}

#[test]
fn erase_rejects_bad_requests() {
    let (j, _) = personal_journal();
    let note = ErasureNote::local("x", "");
    for what in [
        EraseSelector::Slots(vec![(99, 0)]),
        EraseSelector::Slots(vec![(1, 9)]),
        EraseSelector::Match(vec![]),
        EraseSelector::Match(b"not present anywhere".to_vec()),
    ] {
        assert!(
            matches!(j.erase(&what, &note, AT), Err(Fault::Unsupported(_))),
            "{what:?}"
        );
    }
    let mut pending = j.clone();
    pending.append(ROOT, recv("unpersisted")).unwrap();
    assert!(matches!(
        pending.erase(&EraseSelector::All, &note, AT),
        Err(Fault::Unsupported(m)) if m.contains("persisted")
    ));
    let bundle = Journal::parse_evidence(&j.to_bytes()).unwrap().journal;
    assert!(bundle.erase(&EraseSelector::All, &note, AT).is_err());
}

#[test]
fn erasure_of_a_keyed_journal() {
    let mut j = journal(Some(b"k"));
    j.append(ROOT, recv("secret")).unwrap();
    j.mark_persisted(1);
    let e = j
        .erase(&EraseSelector::All, &ErasureNote::local("x", ""), AT)
        .unwrap();
    let back = Journal::parse(&e.file, Some(b"k")).unwrap().journal;
    assert!(back.audit().is_ok());
    assert_eq!(back.entries()[0].hash, j.entries()[0].hash);
}

#[test]
fn audit_reports_erasure_without_a_note() {
    let (j, _) = personal_journal();
    let e = j
        .erase(
            &EraseSelector::Slots(vec![(2, 1)]),
            &ErasureNote::local("x", ""),
            AT,
        )
        .unwrap();
    // Drop the note frame: an erased slot nobody accounts for (a tool that
    // bypassed Pragmatic, or bit rot).
    let note_start = frames(&e.file)[e.note_cursor as usize].0;
    let silent = Journal::parse(&e.file[..note_start], None).unwrap().journal;
    assert!(silent.verify().is_ok(), "the chain still verifies");
    let report = silent.audit();
    assert_eq!(report.unaccounted_erasures, vec![(2, 1)]);
    assert!(!report.is_ok());
}

#[test]
fn audit_reports_and_erase_repairs_an_incomplete_erasure() {
    let (j, _) = personal_journal();
    let e = j
        .erase(
            &EraseSelector::Slots(vec![(2, 1)]),
            &ErasureNote::local("x", ""),
            AT,
        )
        .unwrap();
    // The old frames with the new note appended: the note chains on the
    // old head (hashes never change), but the slot still holds content.
    let note_frame = e.journal.frame_bytes(e.note_cursor).unwrap();
    let mut file = j.to_bytes();
    file.extend_from_slice(&note_frame);
    let half = Journal::parse(&file, None).unwrap().journal;
    assert!(half.verify().is_ok());
    let report = half.audit();
    assert_eq!(report.erasure_incomplete, vec![(2, 1)]);
    assert!(!report.is_ok());
    let fixed = half
        .erase(
            &EraseSelector::Slots(vec![(2, 1)]),
            &ErasureNote::local("x", "repair"),
            AT,
        )
        .unwrap();
    assert!(fixed.journal.audit().is_ok());
}

#[test]
fn audit_reports_invalid_erasure_notes() {
    let (mut j, _) = personal_journal();
    let out_of_range = j
        .append_server_note(AT, note::ERASURE, r#"{"slots":[[1,9]]}"#, vec![])
        .unwrap();
    let not_earlier = j
        .append_server_note(AT, note::ERASURE, r#"{"slots":[[999,0]]}"#, vec![])
        .unwrap();
    let malformed = j
        .append_server_note(AT, note::ERASURE, r#"{"slots":"all"}"#, vec![])
        .unwrap();
    let bad_pair = j
        .append_server_note(
            AT,
            note::ERASURE,
            r#"{"slots":[[1,1,1],[1,-1],[1.0,1]]}"#,
            vec![],
        )
        .unwrap();
    let report = j.audit();
    assert_eq!(
        report.invalid_erasure_notes,
        vec![out_of_range, not_earlier, malformed, bad_pair]
    );
    assert_eq!(report.first_bad, None);
}

#[test]
fn erasure_notes_list_only_earlier_slots() {
    let (mut j, _) = personal_journal();
    // A note cannot account for itself or for later entries.
    let c = j.len();
    j.append_server_note(
        AT,
        note::ERASURE,
        &format!(r#"{{"slots":[[{c},0]]}}"#),
        vec!["r".into()],
    )
    .unwrap();
    assert_eq!(j.audit().invalid_erasure_notes, vec![c]);
}

// ---------------------------------------------------------------------------
// Format 1 (spec 2.16)
// ---------------------------------------------------------------------------

fn v1_events() -> Vec<crate::journal_v1::Event> {
    use crate::journal_v1::Event as V1;
    vec![
        V1::Program {
            name: "agent".into(),
            hash: "abc".into(),
        },
        V1::OracleDraw {
            prompt: "plan".into(),
            outcome: "step".into(),
            provenance: "seeded".into(),
        },
        V1::EffectIntent {
            name: "write".into(),
            arg: "x".into(),
        },
        V1::EffectCommit {
            name: "write".into(),
            result: "ok".into(),
        },
        V1::ChannelRecv {
            channel: "c".into(),
            value: "v".into(),
        },
        V1::EffectCompensated { name: "w".into() },
        V1::Clock { nanos: 99 },
    ]
}

/// The bytes the 0.5 writer produces.
fn v1_file(key: Option<&[u8]>) -> Vec<u8> {
    let dir = crate::backend::test_dir("v1-file");
    let path = dir.join("run.journal");
    let mut j = match key {
        Some(k) => crate::journal_v1::Journal::create_keyed(&path, k).unwrap(),
        None => crate::journal_v1::Journal::create(&path).unwrap(),
    };
    for e in v1_events() {
        j.append(e).unwrap();
    }
    j.sync().unwrap();
    std::fs::read(&path).unwrap()
}

#[test]
fn format_1_reads_as_legacy_entries() {
    let file = v1_file(None);
    let parsed = Journal::parse(&file, None).unwrap();
    assert_eq!(parsed.tail_len, 0);
    let j = parsed.journal;
    assert_eq!(j.format(), 1);
    assert_eq!(j.len(), v1_events().len() as u64);
    assert!(matches!(
        &j.entries()[1].event,
        Event::Legacy(LegacyEvent::OracleDraw { prompt, .. }) if prompt.as_bytes() == b"plan"
    ));
    assert!(j
        .entries()
        .iter()
        .all(|e| e.branch.is_empty() && e.slots.is_empty()));
    assert!(j.verify().is_ok());
    assert!(j.audit().is_ok());
    assert_eq!(j.to_bytes(), file);
    assert_eq!(j.program_entries().len(), v1_events().len());
}

#[test]
fn format_1_is_read_only() {
    let mut j = Journal::parse(&v1_file(None), None).unwrap().journal;
    assert_eq!(
        unsupported(j.append(ROOT, Event::Clock { nanos: 1 })),
        FORMAT1_READ_ONLY
    );
    assert!(matches!(
        j.erase(&EraseSelector::All, &ErasureNote::local("x", ""), AT),
        Err(Fault::Unsupported(m)) if m == FORMAT1_READ_ONLY
    ));
}

#[test]
fn format_1_keying_torn_tails_and_corruption() {
    let keyed = v1_file(Some(b"k"));
    assert!(Journal::parse(&keyed, Some(b"k"))
        .unwrap()
        .journal
        .verify()
        .is_ok());
    // Nothing in a format 1 header says it is keyed: without the key the
    // first link fails, and that is an error, not a torn tail.
    assert_eq!(corrupt_at(Journal::parse(&keyed, None)).0, 0);
    assert_eq!(corrupt_at(Journal::parse(&keyed, Some(b"wrong"))).0, 0);

    let file = v1_file(None);
    let n = v1_events().len() as u64;
    let parsed = Journal::parse(&file[..file.len() - 5], None).unwrap();
    assert_eq!((parsed.journal.len(), parsed.tail_len > 0), (n - 1, true));
    let mut zeros = file.clone();
    zeros.resize(file.len() + 100, 0);
    assert_eq!(Journal::parse(&zeros, None).unwrap().journal.len(), n);
    // Flip a payload byte of entry 1: its successor still chains from its
    // stored hash.
    let mut flipped = file.clone();
    let first_len = u32::from_le_bytes(file[12..16].try_into().unwrap()) as usize;
    let second = 12 + 4 + first_len + 32;
    flipped[second + 4 + 10] ^= 1;
    assert_eq!(corrupt_at(Journal::parse(&flipped, None)).0, 1);
}

// ---------------------------------------------------------------------------
// Evidence journals
// ---------------------------------------------------------------------------

#[test]
fn evidence_journals_accept_withheld_slots() {
    let (j, _) = personal_journal();
    let mut file = j.to_bytes();
    // Withhold slot (2, 1): replace it by state 3 and its commitment.
    let rec = record(&file, 2);
    let e = &j.entries()[2];
    let mut withheld = Rec::new(2, vec![u64f(1), s(r#"{"outcome":"ok"}"#)], vec![]);
    withheld.slots = vec![sealed_like(&rec, e, 0), stateful(3, e.slots[1].commitment)];
    file = replace_record(&file, 2, &withheld.bytes());
    assert!(Journal::parse(&file, None).is_err());
    let bundle = Journal::parse_evidence(&file).unwrap();
    assert_eq!(bundle.tail_len, 0);
    let b = bundle.journal;
    assert_eq!(b.entries()[2].event.slot_contents()[1], &Content::Withheld);
    assert!(b.verify().is_ok());
    assert!(b.audit().is_ok());
    assert_eq!(b.head(), j.head());
}

/// The raw bytes of slot `k` of a stored record (sealed), cut out of `rec`.
fn sealed_like(rec: &[u8], e: &Entry, k: usize) -> Vec<u8> {
    let content = e.event.slot_contents()[k]
        .value()
        .unwrap()
        .as_bytes()
        .to_vec();
    let commitment = e.slots[k].commitment;
    let at = rec
        .windows(32)
        .position(|w| w == commitment)
        .expect("commitment in record");
    let mut out = vec![1u8];
    out.extend_from_slice(&rec[at..at + 32 + SALT_LEN + 4]);
    out.extend_from_slice(&content);
    out
}
