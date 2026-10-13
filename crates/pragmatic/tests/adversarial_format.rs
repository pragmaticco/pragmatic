//! Regression tests from the adversarial review of journal format 2:
//! classification of damaged files, cross-reference checks on replay,
//! strict-JSON cost, decoded size and erasure coverage. Each test is a
//! scenario the review found failing; its comment names the defect it
//! guards against.

use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::Instant;

use pragmatic::journal::{
    note, EraseSelector, ErasureNote, JournalError, Parsed, HEADER_LEN, META, ROOT,
};
use pragmatic::{
    Backend, Content, DirBackend, EffectOutcome, Event, Fault, Journal, MemoryBackend, Mode,
    RefusingOracle, RunOptions, Runtime, Value,
};

const AT: u64 = 1_760_000_000_000_000_000;

fn fixed_clock() -> u64 {
    AT
}

fn run_start(id: &str) -> Event {
    Event::Note {
        kind: note::RUN_START.into(),
        data: format!("{{\"format\":2,\"run_id\":\"{id}\"}}"),
        payload: vec![],
    }
}

/// `run.start` plus `n` clock reads on the root branch, with a fixed `at`
/// so every hash is deterministic (clock entries have no salted slots).
fn clocks(id: &str, n: u64) -> Journal {
    let mut j = Journal::new(None);
    j.set_clock(fixed_clock);
    j.append(META, run_start(id)).unwrap();
    for i in 0..n {
        j.append(ROOT, Event::Clock { nanos: 1000 + i }).unwrap();
    }
    j
}

/// `(frame start, frame end)` of every frame of a format 2 file.
fn frames(file: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut pos = HEADER_LEN;
    while pos + 4 <= file.len() {
        let len = u32::from_le_bytes(file[pos..pos + 4].try_into().unwrap()) as usize;
        let end = pos + 4 + len + 32;
        if end > file.len() {
            break;
        }
        out.push((pos, end));
        pos = end;
    }
    out
}

fn describe(r: &Result<Parsed, JournalError>) -> String {
    match r {
        Ok(p) => format!(
            "parsed {} entries with a {}-byte tail",
            p.journal.len(),
            p.tail_len
        ),
        Err(e) => format!("error: {e}"),
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "pragmatic-adv-{name}-{}-{}",
        std::process::id(),
        AT
    ));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

// ---------------------------------------------------------------------------
// Torn versus corrupt (spec 2.14)
// ---------------------------------------------------------------------------

/// A crash that leaves the last 1 to 3 bytes of the final frame's hash
/// unwritten (the file was extended, the last block never reached the disk,
/// so it reads back as zeros) is a torn tail: nothing follows the failing
/// frame, so spec 2.14 says tail. The parser's "intact frame whose link
/// fails" heuristic only forgives a zero suffix of 4 or more bytes, so this
/// genuine crash artifact is reported as corruption and the run can never
/// be resumed (a writer never truncates corruption).
#[test]
fn adv_hash_suffix_of_1_to_3_unwritten_bytes_is_a_torn_tail_not_corruption() {
    let file = clocks("r", 6).to_bytes();
    let n = frames(&file).len() as u64;
    let (last_start, last_end) = *frames(&file).last().unwrap();
    assert_eq!(last_end, file.len());
    for zeros in 1..=3usize {
        let mut torn = file.clone();
        let end = torn.len();
        torn[end - zeros..].fill(0);
        let parsed = Journal::parse(&torn, None);
        assert!(
            matches!(&parsed, Ok(p) if p.journal.len() == n - 1
                && p.tail_len == (last_end - last_start) as u64),
            "{zeros} unwritten trailing hash byte(s): expected a torn tail of the \
             last frame, got {}",
            describe(&parsed)
        );
    }
}

/// Eight zero bytes in the middle of the file (a lost or zeroed sector
/// spanning a frame boundary: the last 4 bytes of frame k's hash and frame
/// k+1's length prefix) leave frames k+2.. intact and chaining. That is
/// corruption, never a tail; but the classifier only looks for a successor
/// at cursor k+1, so it calls everything from frame k on a torn tail.
#[test]
fn adv_zeroed_span_across_a_mid_file_frame_boundary_is_corruption_not_a_torn_tail() {
    let file = clocks("r", 20).to_bytes();
    let all = frames(&file);
    let k = 5;
    let (_, end_k) = all[k];
    let mut damaged = file.clone();
    damaged[end_k - 4..end_k + 4].fill(0);
    let parsed = Journal::parse(&damaged, None);
    assert!(
        matches!(&parsed, Err(JournalError::Corrupt { cursor, .. }) if *cursor == k as u64),
        "8 zero bytes at the boundary of frames {k} and {}: expected corruption at \
         cursor {k}, got {}",
        k + 1,
        describe(&parsed)
    );
}

/// The same with one whole small frame zeroed in the middle of the file:
/// its stored hash is gone, so the successor cannot be found by the
/// "32 bytes before it" scan, and the 15 intact frames after it are thrown
/// into the tail.
#[test]
fn adv_one_wholly_zeroed_mid_file_frame_is_corruption_not_a_torn_tail() {
    let file = clocks("r", 20).to_bytes();
    let all = frames(&file);
    let k = 5;
    let (start_k, end_k) = all[k];
    let mut damaged = file.clone();
    damaged[start_k..end_k].fill(0);
    let parsed = Journal::parse(&damaged, None);
    assert!(
        matches!(&parsed, Err(JournalError::Corrupt { cursor, .. }) if *cursor == k as u64),
        "frame {k} zeroed with {} intact frames after it: expected corruption, got {}",
        all.len() - k - 1,
        describe(&parsed)
    );
}

/// The consequence of the misclassification above through the real
/// backend: a lock holder "repairs" mid-file damage by moving 15
/// acknowledged entries out of the journal and continuing the run without
/// them (a resume would then re-perform their effects).
#[test]
fn adv_dir_checkout_never_truncates_acknowledged_entries_after_mid_file_damage() {
    let dir = temp_dir("midfile");
    let b = DirBackend::new(&dir).unwrap();
    let file = clocks("r", 20).to_bytes();
    let all = frames(&file);
    let k = 5;
    let (_, end_k) = all[k];
    let mut damaged = file.clone();
    damaged[end_k - 4..end_k + 4].fill(0);
    let path = b.journal_path("r");
    fs::write(&path, &damaged).unwrap();

    let result = b.checkout("r", false, None);
    let outcome = match &result {
        Ok(co) => format!(
            "checkout succeeded with {} entries (of {}), torn = {:?}, file now {} bytes",
            co.journal.len(),
            all.len(),
            co.torn.as_ref().map(|t| t.bytes),
            fs::metadata(&path).unwrap().len()
        ),
        Err(f) => format!("{f}"),
    };
    let refused = result.is_err();
    drop(result);
    let _ = fs::remove_dir_all(&dir);
    assert!(
        refused,
        "mid-file damage must be refused as corruption, never truncated: {outcome}"
    );
}

/// The worst case of the same hole: zeroing the first frame (`run.start`)
/// makes the whole journal a "torn tail" with an empty valid prefix, so the
/// run-id check passes vacuously and a checkout moves every entry of the run
/// aside and starts it over (re-performing every effect on resume).
#[test]
fn adv_zeroed_first_frame_does_not_let_a_checkout_restart_the_run() {
    let dir = temp_dir("first-frame");
    let b = DirBackend::new(&dir).unwrap();
    let file = clocks("r", 20).to_bytes();
    let (start0, end0) = frames(&file)[0];
    let mut damaged = file.clone();
    damaged[start0..end0].fill(0);
    let path = b.journal_path("r");
    fs::write(&path, &damaged).unwrap();
    let result = b.checkout("r", false, None);
    let outcome = match &result {
        Ok(co) => format!(
            "checkout succeeded with {} entries, torn = {:?} bytes",
            co.journal.len(),
            co.torn.as_ref().map(|t| t.bytes)
        ),
        Err(f) => format!("{f}"),
    };
    let refused = result.is_err();
    drop(result);
    let _ = fs::remove_dir_all(&dir);
    assert!(
        refused,
        "21 entries after a zeroed first frame must be corruption: {outcome}"
    );
}

// ---------------------------------------------------------------------------
// Cross-references between results and intents
// ---------------------------------------------------------------------------

/// A result record on the root branch naming `intent`, encoded by hand and
/// chained after `prev` at `cursor`: what a writer that skips
/// `Journal::append`'s checks (or edits an unkeyed file) produces. `kind` is
/// 2 (`DrawResult`) or 5 (`EffectResult`).
fn forged_result(prev: &[u8; 32], cursor: u64, kind: u8, intent: u64) -> Vec<u8> {
    let fields: Vec<Vec<u8>> = match kind {
        2 => vec![
            intent.to_le_bytes().to_vec(),
            br#"{"outcome":"ok"}"#.to_vec(),
        ],
        _ => vec![intent.to_le_bytes().to_vec(), b"ok".to_vec(), Vec::new()],
    };
    let nslots: u8 = if kind == 2 { 2 } else { 1 };
    let mut head = vec![kind];
    head.extend_from_slice(&AT.to_le_bytes());
    head.push(0); // depth: the root branch
    head.push(fields.len() as u8);
    for f in &fields {
        head.extend_from_slice(&(f.len() as u32).to_le_bytes());
        head.extend_from_slice(f);
    }
    head.push(nslots);
    let mut record = head.clone();
    let mut skeleton = head;
    let (salt, content) = ([7u8; 16], b"forged");
    let mut pre = b"pragmatic/v2/slot".to_vec();
    pre.extend_from_slice(&salt);
    pre.extend_from_slice(&(content.len() as u64).to_le_bytes());
    pre.extend_from_slice(content);
    let commitment = pragmatic::sha256::sha256(&pre);
    for _ in 0..nslots {
        record.push(1);
        record.extend_from_slice(&commitment);
        record.extend_from_slice(&salt);
        record.extend_from_slice(&(content.len() as u32).to_le_bytes());
        record.extend_from_slice(content);
        skeleton.push(1);
        skeleton.extend_from_slice(&commitment);
    }
    let mut chained = prev.to_vec();
    chained.extend_from_slice(&cursor.to_le_bytes());
    chained.extend_from_slice(&skeleton);
    let mut frame = (record.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&record);
    frame.extend_from_slice(&pragmatic::sha256::sha256(&chained));
    frame
}

/// A result naming an intent of the other kind (an `EffectResult` for a
/// `DrawIntent`, or the reverse) used to be written by `Journal::append`,
/// read by `Journal::parse` and passed by `verify()`, and then panicked the
/// session on replay. Now the journal refuses to write it, a reader
/// refuses a file holding it as corruption at its cursor (never a torn
/// tail), a verifier reports it, and replay is a fault.
fn mismatched_result_is_refused(intent_event: Event, forged: Event, kind: u8) {
    let mut j = Journal::new(None);
    j.append(META, run_start("r")).unwrap();
    let intent = j.append(ROOT, intent_event.clone()).unwrap();
    assert!(
        matches!(j.append(ROOT, forged), Err(Fault::Unsupported(_))),
        "Journal::append wrote a result for an intent of the other kind"
    );
    let cursor = j.len();
    let mut bytes = j.to_bytes();
    bytes.extend_from_slice(&forged_result(&j.head(), cursor, kind, intent));
    let parsed = Journal::parse(&bytes, None);
    assert!(
        matches!(&parsed, Err(JournalError::Corrupt { cursor: c, .. }) if *c == cursor),
        "{}",
        describe(&parsed)
    );
    let (_, report) = Journal::audit_bytes(&bytes, None).unwrap();
    assert_eq!(report.first_bad, Some(cursor));

    let backend = MemoryBackend::new();
    backend.set_bytes("r", bytes).unwrap();
    let rt = Runtime::with_backend(Box::new(backend.clone()), RefusingOracle);
    assert_eq!(rt.verify("r").unwrap().first_bad, Some(cursor));
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut attempt = rt.begin("r", Mode::Replay, RunOptions::default())?;
        let session = attempt.session();
        match &intent_event {
            Event::DrawIntent { .. } => session
                .draw_begin(&ROOT.to_vec(), "p", vec![Value::from("hello")])
                .map(|_| ()),
            _ => session
                .effect_begin(&ROOT.to_vec(), "send", Value::from("a"))
                .map(|_| ()),
        }
    }));
    match outcome {
        Err(_) => panic!("strict replay panicked; expected a Fault"),
        Ok(r) => assert!(r.is_err(), "expected a Fault, got {r:?}"),
    }
    // A writer refuses it too, and leaves the file as it was.
    let before = backend.bytes("r").unwrap();
    assert!(backend.checkout("r", false, None).is_err());
    assert_eq!(backend.bytes("r").unwrap(), before);
}

#[test]
fn adv_effect_result_naming_a_draw_intent_faults_instead_of_panicking() {
    mismatched_result_is_refused(
        Event::DrawIntent {
            provenance: "p".into(),
            parts: vec![Content::from("hello")],
        },
        Event::EffectResult {
            intent: 1,
            outcome: EffectOutcome::Ok,
            error_kind: String::new(),
            payload: Some(Content::from("x")),
        },
        5,
    );
}

#[test]
fn adv_draw_result_naming_an_effect_intent_faults_instead_of_panicking() {
    mismatched_result_is_refused(
        Event::EffectIntent {
            name: "send".into(),
            arg: Content::from("a"),
        },
        Event::DrawResult {
            intent: 1,
            meta: r#"{"outcome":"ok"}"#.into(),
            head: Content::from("h"),
            body: Content::from("b"),
        },
        2,
    );
}

/// A result must also sit on its intent's branch and come after it.
#[test]
fn adv_results_complete_earlier_intents_on_their_own_branch() {
    let mut j = Journal::new(None);
    j.append(META, run_start("r")).unwrap();
    let effect = j
        .append(
            ROOT,
            Event::EffectIntent {
                name: "send".into(),
                arg: Content::from("a"),
            },
        )
        .unwrap();
    let result = |intent| Event::EffectResult {
        intent,
        outcome: EffectOutcome::Ok,
        error_kind: String::new(),
        payload: Some(Content::from("x")),
    };
    for (branch, intent) in [(&[0u32][..], effect), (ROOT, 2), (ROOT, 99), (ROOT, 0)] {
        assert!(
            matches!(j.append(branch, result(intent)), Err(Fault::Unsupported(_))),
            "{branch:?} {intent}"
        );
    }
    assert!(j.append(ROOT, result(effect)).is_ok());
}

// ---------------------------------------------------------------------------
// Strict JSON cost on adversarial input
// ---------------------------------------------------------------------------

/// Every JSON field of every record is checked for duplicate keys with a
/// pairwise scan per object, so parse time is quadratic in an object's key
/// count. A ~300 KB note (30k keys) takes seconds; a 10 MB one (1M keys,
/// far below the 256 MiB record limit) takes on the order of an hour in a
/// release build. `Journal::parse` and `parse_evidence` read adversarial
/// files (CLI verify, evidence verification, the server's append path).
#[test]
fn adv_duplicate_key_check_is_not_quadratic() {
    let n = 30_000usize;
    let mut data = String::from("{");
    for i in 0..n {
        if i > 0 {
            data.push(',');
        }
        data.push_str(&format!("\"k{i}\":0"));
    }
    data.push('}');
    let mut j = Journal::new(None);
    j.append(
        META,
        Event::Note {
            kind: note::RUN_START.into(),
            data,
            payload: vec![],
        },
    )
    .unwrap();
    let bytes = j.to_bytes();
    let t = Instant::now();
    Journal::parse(&bytes, None).unwrap();
    let took = t.elapsed();
    assert!(
        took.as_millis() < 500,
        "parsing one {}-byte record took {took:?}",
        bytes.len()
    );
}

// ---------------------------------------------------------------------------
// Erasure coverage
// ---------------------------------------------------------------------------

/// A torn tail moved aside to `<64hex>.torn-<ms>` holds the content of the
/// partly written frame. Erasure (even `EraseSelector::All`, "shredding a
/// run") rewrites only the journal, so the content survives in the run's
/// directory after a successful erase.
#[test]
fn adv_erase_all_leaves_content_in_moved_torn_tails() {
    const SECRET: &str = "patient 4411 diagnosis: confidential";
    let dir = temp_dir("torn-erase");
    let b = DirBackend::new(&dir).unwrap();
    {
        let mut co = b.checkout("r", true, None).unwrap();
        co.journal.append(META, run_start("r")).unwrap();
        co.journal
            .append(
                ROOT,
                Event::ChannelRecv {
                    channel: "inbox".into(),
                    value: Content::from("public"),
                },
            )
            .unwrap();
        co.persist().unwrap();
        // A crash part-way through the next persist: the frame's content is
        // on disk, its hash is not.
        co.journal
            .append(
                ROOT,
                Event::ChannelRecv {
                    channel: "inbox".into(),
                    value: Content::from(SECRET),
                },
            )
            .unwrap();
        let (_, frames, _) = co.journal.pending().unwrap();
        let partial = frames[..frames.len() - 10].to_vec();
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(b.journal_path("r"))
            .unwrap();
        std::io::Write::write_all(&mut f, &partial).unwrap();
    }
    {
        let mut co = b.checkout("r", false, None).unwrap();
        assert!(co.torn.is_some(), "the partial frame is a torn tail");
        co.erase(&EraseSelector::All, &ErasureNote::local("gdpr", ""))
            .unwrap();
    }
    let mut holders = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let bytes = fs::read(entry.path()).unwrap();
        if bytes.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()) {
            holders.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    let _ = fs::remove_dir_all(&dir);
    assert!(
        holders.is_empty(),
        "after erase(All) the content is still in {holders:?}"
    );
}

// ---------------------------------------------------------------------------
// Decoded size of refs
// ---------------------------------------------------------------------------

/// A hand-built `DrawIntent` record on the root branch whose every slot is a
/// ref to `(tc, ts)` with commitment `commit`, chained after `prev` at
/// `cursor`. Returns the frame bytes and its hash.
fn ref_frame(
    prev: &[u8; 32],
    cursor: u64,
    commit: &[u8; 32],
    tc: u64,
    ts: u8,
    n: usize,
) -> (Vec<u8>, [u8; 32]) {
    let mut head = vec![1u8];
    head.extend_from_slice(&AT.to_le_bytes());
    head.push(0); // depth
    head.push(1); // nfields
    head.extend_from_slice(&1u32.to_le_bytes());
    head.push(b'p');
    head.push(n as u8);
    let mut record = head.clone();
    let mut skeleton = head;
    for _ in 0..n {
        record.push(4);
        record.extend_from_slice(commit);
        record.extend_from_slice(&tc.to_le_bytes());
        record.push(ts);
        skeleton.push(1);
        skeleton.extend_from_slice(commit);
    }
    let mut pre = prev.to_vec();
    pre.extend_from_slice(&cursor.to_le_bytes());
    pre.extend_from_slice(&skeleton);
    let hash = pragmatic::sha256::sha256(&pre);
    let mut frame = (record.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&record);
    frame.extend_from_slice(&hash);
    (frame, hash)
}

/// `Journal::parse` resolves every ref by deep-copying its target's content
/// into the entry, so a file of 42-byte ref slots decodes to the target size
/// times the number of refs. Here a ~300 KB file decodes to ~255 MiB; a
/// 64 MiB target plus 100 KB of refs (2,400 refs) is ~150 GiB, which kills a
/// verifier or server reading an adversarial journal or evidence bundle
/// long before any limit of spec 2.15 applies.
#[test]
fn adv_refs_do_not_multiply_decoded_size() {
    let target = vec![b'x'; 256 * 1024];
    let mut j = Journal::new(None);
    j.set_clock(fixed_clock);
    j.append(META, run_start("r")).unwrap();
    let tc = j
        .append(
            ROOT,
            Event::ChannelRecv {
                channel: "c".into(),
                value: Content::from(target),
            },
        )
        .unwrap();
    let commit = j.entries()[tc as usize].slots[0].commitment;
    let mut file = j.to_bytes();
    let mut prev = j.head();
    for i in 0..4u64 {
        let (frame, hash) = ref_frame(&prev, tc + 1 + i, &commit, tc, 0, 255);
        file.extend_from_slice(&frame);
        prev = hash;
    }
    let parsed = Journal::parse(&file, None).unwrap();
    assert_eq!((parsed.journal.len(), parsed.tail_len), (6, 0));
    // A ref's content is its target's content (spec 2.5): every one of the
    // 1,020 refs reads as the 256 KiB target...
    let contents: Vec<&Value> = parsed
        .journal
        .entries()
        .iter()
        .flat_map(|e| e.event.slot_contents())
        .filter_map(|c| c.value())
        .collect();
    assert_eq!(contents.len(), 1 + 4 * 255);
    assert!(contents.iter().all(|v| v.len() == 256 * 1024));
    // ...but they all share the target's buffer, so the memory a reader
    // holds stays within the file's size.
    let mut buffers: Vec<&Value> = Vec::new();
    for v in contents {
        if !buffers.iter().any(|b| b.shares_bytes_with(v)) {
            buffers.push(v);
        }
    }
    let decoded: usize = buffers.iter().map(|v| v.len()).sum();
    assert!(
        decoded <= file.len(),
        "a {}-byte file decoded to {decoded} bytes of distinct slot content",
        file.len()
    );
    // Verification compares each ref with its target without copying.
    let t = Instant::now();
    assert!(parsed.journal.audit().is_ok());
    assert!(t.elapsed().as_secs() < 5, "audit took {:?}", t.elapsed());
}

// ---------------------------------------------------------------------------
// Runtime::verify on a tampered journal
// ---------------------------------------------------------------------------

/// `Runtime::verify` returns a `VerifyReport` whose `first_bad` names the
/// first bad cursor (spec 2.5, 3.0), and the C ABI maps a failing report to
/// `PRAG_ERR_TAMPERED` with the cursor (header unchanged, spec 3.4). But the
/// snapshot it audits comes from `Journal::parse`, which refuses any
/// mid-file link or commitment failure, so a tampered journal never yields
/// a report: it is `Fault::Io("journal corrupt ...")` (`PRAG_ERR_IO`, no
/// cursor out), indistinguishable from a disk error. Tampering with the
/// last frame instead yields a clean report (`is_ok()`, `PRAG_OK`), the
/// tampered entry silently dropped as a "torn tail".
#[test]
fn adv_runtime_verify_reports_tampering_as_a_report_not_an_io_error() {
    let mut j = Journal::new(None);
    j.append(META, run_start("r")).unwrap();
    for i in 0..4 {
        j.append(
            ROOT,
            Event::ChannelRecv {
                channel: "c".into(),
                value: Content::from(format!("message {i}")),
            },
        )
        .unwrap();
    }
    let file = j.to_bytes();
    let all = frames(&file);

    // A content byte of cursor 2 changed.
    let (_, end) = all[2];
    let mut mid = file.clone();
    mid[end - 32 - 1] ^= 0x01;
    let backend = MemoryBackend::new();
    backend.set_bytes("r", mid).unwrap();
    let rt = Runtime::with_backend(Box::new(backend.clone()), RefusingOracle);
    let mid_result = rt.verify("r");

    // A content byte of the last entry changed.
    let (_, end) = *all.last().unwrap();
    let mut last = file.clone();
    last[end - 32 - 1] ^= 0x01;
    backend.set_bytes("r", last).unwrap();
    let last_result = rt.verify("r");

    let mid_ok = matches!(&mid_result, Ok(r) if r.first_bad == Some(2));
    let last_ok = matches!(&last_result, Ok(r) if !r.is_ok());
    assert!(
        mid_ok && last_ok,
        "tampering at cursor 2 -> {:?}; tampering at the last cursor -> {:?}",
        mid_result.map(|r| (r.first_bad, r.is_ok(), r.torn_bytes)),
        last_result.map(|r| (r.first_bad, r.is_ok(), r.torn_bytes)),
    );
}

#[allow(dead_code)]
fn _fault_is_used(_: Fault) {}
