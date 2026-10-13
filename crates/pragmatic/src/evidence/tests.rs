//! Evidence bundles against the fixtures in `tests/fixtures/evidence`
//! (see its README): every check of design 5.3, and the adversarial set of
//! design section 9, each failing with its own code.
//!
//! RFC 3161 signatures are checked here by a stand-in for OpenSSL that
//! accepts a token exactly when it was issued under the root it is checked
//! against; the CLI's tests run the same bundles through `openssl ts
//! -verify`. Everything else (Ed25519, Merkle proofs, the journal) is
//! checked for real.

use std::collections::HashMap;
use std::path::PathBuf;

use super::*;
use crate::encoding::base64_encode;
use crate::journal::{note, EraseSelector, ErasureNote, Event, Journal, META, ROOT};
use crate::note::VerifierKey;
use crate::value::Value;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/evidence")
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn bundle_named(name: &str) -> Bundle {
    Bundle::from_json(&fixture(name)).unwrap()
}

fn bundle() -> Bundle {
    bundle_named("bundle.json")
}

fn vkey(name: &str) -> VerifierKey {
    let text = String::from_utf8(fixture(&format!("trust/{name}"))).unwrap();
    VerifierKey::parse(text.trim()).unwrap()
}

fn witness_key(name: &str) -> WitnessKey {
    WitnessKey {
        operator: "Fixture Witness".into(),
        key: vkey(name),
        not_before: None,
        not_after: None,
    }
}

fn tsa_roots() -> Vec<TsaRoot> {
    ["a", "b"]
        .iter()
        .map(|x| TsaRoot {
            operator: format!("Fixture TSA {}", x.to_uppercase()),
            path: dir().join(format!("trust/tsa-{x}-root.pem")),
        })
        .collect()
}

fn full_trust() -> TrustPolicy {
    TrustPolicy {
        tsa_roots: tsa_roots(),
        witness_keys: vec![witness_key("witness.vkey")],
        log_keys: vec![vkey("log.vkey")],
        ..TrustPolicy::default()
    }
}

/// Full trust without the log key, for unsigned bundles (local ones, and
/// tampered copies): a pinned log key requires the bundle's signature.
fn open_log() -> TrustPolicy {
    TrustPolicy {
        log_keys: Vec::new(),
        ..full_trust()
    }
}

/// Stands in for `openssl ts -verify`: a token verifies against a root
/// exactly when the TSA certificate that came with it was issued under
/// that root, which the fixture's TSA URLs say.
struct FakeOpenSsl {
    issued_under: HashMap<String, String>,
}

impl FakeOpenSsl {
    fn new() -> FakeOpenSsl {
        let mut issued_under = HashMap::new();
        for b in ["bundle.json", "bundle-hmac.json"] {
            for a in &bundle_named(b).anchors {
                for w in &a.witnesses {
                    if let Witness::Rfc3161 { tsa, certs_pem, .. } = w {
                        let root = if tsa.contains("tsa-a") {
                            "tsa-a-root.pem"
                        } else {
                            "tsa-b-root.pem"
                        };
                        issued_under.insert(certs_pem.clone(), root.to_string());
                    }
                }
            }
        }
        FakeOpenSsl { issued_under }
    }
}

impl TsaVerifier for FakeOpenSsl {
    fn verify(&self, check: &TsaCheck<'_>) -> TsaResult {
        let root = check.root.file_name().unwrap().to_string_lossy();
        assert!(check.at_time > 1_700_000_000, "genTime + 1 is passed");
        match self.issued_under.get(check.certs_pem) {
            Some(r) if *r == root => TsaResult::Verified,
            _ => TsaResult::Rejected("unable to get local issuer certificate".into()),
        }
    }
}

fn check(b: &Bundle, policy: &TrustPolicy) -> EvidenceReport {
    verify(b, policy, &FakeOpenSsl::new())
}

fn check_audit(b: &Bundle, policy: &TrustPolicy, audit: &Audit) -> EvidenceReport {
    verify_with(b, policy, &FakeOpenSsl::new(), audit)
}

fn codes(r: &EvidenceReport) -> Vec<&'static str> {
    r.findings.iter().map(|f| f.code.as_str()).collect()
}

/// The report fails with `code` (and the verdict is FAILED).
fn assert_fails(r: &EvidenceReport, code: Code) {
    assert_eq!(r.verdict, Verdict::Failed, "{:?}", codes(r));
    assert!(r.has(code), "expected {code}, got {:?}", codes(r));
}

/// An unsigned copy, for tampering without tripping the bundle signature.
fn unsigned(mut b: Bundle) -> Bundle {
    b.signature = None;
    b
}

fn with_log(log: AnchorLog) -> Audit {
    Audit {
        log: Some(log),
        witness_logs: Vec::new(),
    }
}

fn with_witness_log(wl: WitnessLog) -> Audit {
    Audit {
        log: None,
        witness_logs: vec![wl],
    }
}

// ---------------------------------------------------------------------------
// The format
// ---------------------------------------------------------------------------

#[test]
fn fixtures_round_trip_canonically() {
    for name in ["bundle.json", "bundle-hmac.json", "local.json"] {
        let bytes = fixture(name);
        let b = Bundle::from_json(&bytes).unwrap();
        let doc = crate::json::Json::parse_bytes(&bytes).unwrap();
        assert_eq!(b.to_json(), doc.canonical_string(), "{name}");
        assert_eq!(Bundle::from_json(b.to_json().as_bytes()).unwrap(), b);
    }
}

fn verify_text(text: &str) -> EvidenceReport {
    verify_bytes(
        text.as_bytes(),
        &full_trust(),
        &FakeOpenSsl::new(),
        &Audit::default(),
    )
    .1
}

#[test]
fn strict_json_and_unknown_keys() {
    let text = String::from_utf8(fixture("bundle.json")).unwrap();
    let dup = text.replacen("\"generator\":", "\"generator\": \"x\", \"generator\":", 1);
    assert_fails(&verify_text(&dup), Code::BundleJson);
    assert_fails(&verify_text(&format!("{text}x")), Code::BundleJson);
    let unknown = text.replacen('{', "{\"verified\": true,", 1);
    assert_fails(&verify_text(&unknown), Code::BundleSchema);
    // A missing key, a wrong format, uppercase hex, a fractional integer.
    for bad in [
        text.replacen("\"independent\": true,", "", 1),
        text.replacen("pragmatic-evidence/1", "pragmatic-evidence/2", 1),
        uppercase_first_digest(&text),
        text.replacen("\"seq\": 0", "\"seq\": 0.0", 1),
    ] {
        assert_ne!(bad, text);
        assert!(matches!(
            Bundle::from_json(bad.as_bytes()),
            Err(BundleError::Schema(_))
        ));
    }
}

/// The text with the first anchor digest's hex in upper case.
fn uppercase_first_digest(text: &str) -> String {
    let at = text.find("\"anchor_digest\": \"").unwrap() + "\"anchor_digest\": \"".len();
    format!(
        "{}{}{}",
        &text[..at],
        text[at..at + 64].to_uppercase(),
        &text[at + 64..]
    )
}

#[test]
fn signature_message_is_the_canonical_bundle_without_the_signature() {
    let b = bundle();
    let mut doc = crate::json::Json::parse_bytes(&fixture("bundle.json")).unwrap();
    if let crate::json::Json::Object(members) = &mut doc {
        members.retain(|(k, _)| k != "signature");
    }
    assert_eq!(
        b.signature_message(),
        crate::sha256::sha256(doc.canonical_string().as_bytes())
    );
}

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

#[test]
fn fully_pinned_bundle_is_verified() {
    let r = check(&bundle(), &full_trust());
    assert_eq!(r.verdict, Verdict::Verified, "{:#?}", r.findings);
    assert_eq!(r.exit_code(), 0);
    assert_eq!(r.failures().count(), 0);
    assert_eq!(r.entries, 32);
    assert_eq!(r.anchored_entries, 32);
    assert!(matches!(
        r.bundle_signature,
        SignatureStatus::Verified { .. }
    ));
    assert_eq!(r.anchors.len(), 3);
    for a in &r.anchors {
        assert!(a.sound && a.independent);
        assert_eq!(
            a.trusted_operators,
            ["fixture-tsa-a", "fixture-tsa-b", "fixture-witness"]
        );
        let server = &a.witnesses[0];
        assert_eq!(server.kind, "server-ed25519");
        assert_eq!(server.class, WitnessClass::OperatorControlled);
        assert!(a.earliest.is_some());
    }
    assert_eq!(
        r.anchors.iter().map(|a| a.entries).collect::<Vec<_>>(),
        [6, 20, 32]
    );
    for step in ["1", "2", "3", "4", "5", "6", "7", "8", "10"] {
        assert!(r.checks.iter().any(|c| c.step == step), "step {step}");
    }
    assert!(r.checks.iter().all(|c| c.status != CheckStatus::Fail));
}

#[test]
fn hmac_anchored_bundle_is_verified() {
    let b = bundle_named("bundle-hmac.json");
    assert!(b.anchor_id.is_some());
    let r = check(&b, &full_trust());
    assert_eq!(r.verdict, Verdict::Verified, "{:#?}", r.findings);
    // Without the per-run key the leaves name another run.
    let mut no_key = unsigned(b);
    no_key.anchor_id = None;
    assert_fails(&check(&no_key, &full_trust()), Code::RunIdMismatch);
}

#[test]
fn nothing_pinned_means_unanchored() {
    let r = check(&bundle(), &TrustPolicy::default());
    assert_eq!(r.verdict, Verdict::Unanchored, "{:#?}", r.findings);
    assert_eq!(r.exit_code(), 3);
    assert_eq!(r.bundle_signature, SignatureStatus::OperatorAsserted);
    assert!(r.has(Code::TsaUntrusted));
    assert!(r.has(Code::CosignatureUntrusted));
    assert!(r.has(Code::OperatorAsserted));
    for a in &r.anchors {
        assert!(a.sound && !a.independent);
        assert!(a.trusted_operators.is_empty());
    }
}

#[test]
fn a_token_that_verifies_for_two_operators_counts_for_neither() {
    // TSA A's anchors pinned again under another operator's name: its
    // tokens verify under both, so neither may count them (design 5.2).
    let mut roots = tsa_roots();
    roots.push(TsaRoot {
        operator: "Someone Else".into(),
        path: dir().join("trust/tsa-a-root.pem"),
    });
    let r = check(
        &bundle(),
        &TrustPolicy {
            tsa_roots: roots,
            ..full_trust()
        },
    );
    assert!(r.has(Code::TsaAmbiguous), "{:?}", codes(&r));
    for a in &r.anchors {
        for op in ["fixture-tsa-a", "someone-else"] {
            assert!(
                !a.trusted_operators.iter().any(|t| t == op),
                "{op} counted: {:?}",
                a.trusted_operators
            );
        }
        assert!(a.trusted_operators.iter().any(|t| t == "fixture-tsa-b"));
    }
    // The same anchors pinned twice for one operator are not ambiguous.
    let mut roots = tsa_roots();
    roots.push(TsaRoot {
        operator: "fixture  tsa_a".into(),
        path: dir().join("trust/tsa-a-root.pem"),
    });
    let r = check(
        &bundle(),
        &TrustPolicy {
            tsa_roots: roots,
            ..full_trust()
        },
    );
    assert!(!r.has(Code::TsaAmbiguous), "{:?}", codes(&r));
    assert_eq!(r.verdict, Verdict::Verified, "{:#?}", r.findings);
}

#[test]
fn one_operator_is_not_independent_unless_the_minimum_allows_it() {
    let policy = TrustPolicy {
        tsa_roots: tsa_roots(),
        witness_keys: vec![witness_key("witness.vkey")],
        ..TrustPolicy::default()
    };
    let r = verify(&bundle(), &policy, &NoTsaVerifier);
    assert_eq!(r.verdict, Verdict::Unanchored);
    assert!(r.has(Code::TsaUnchecked));
    let one = TrustPolicy {
        min_operators: 1,
        ..policy
    };
    assert_eq!(
        verify(&bundle(), &one, &NoTsaVerifier).verdict,
        Verdict::Verified
    );
}

#[test]
fn aliased_operators_count_once() {
    // Both TSA roots pinned under names that alias to one operator.
    let mut policy = full_trust();
    policy.witness_keys.clear();
    policy.tsa_roots[0].operator = "Entrust".into();
    policy.tsa_roots[1].operator = "Sectigo".into();
    let r = check(&bundle(), &policy);
    assert_eq!(r.verdict, Verdict::Unanchored);
    assert_eq!(r.anchors[0].trusted_operators, ["sectigo"]);
    assert!(
        r.has(Code::OperatorMismatch),
        "the bundle names other operators"
    );
}

#[test]
fn an_unwitnessed_suffix_is_partial() {
    let mut b = unsigned(bundle());
    b.anchors[2].witnesses.clear();
    let r = check(&b, &open_log());
    assert_eq!(
        r.verdict,
        Verdict::Partial { unanchored: 12 },
        "{:#?}",
        r.findings
    );
    assert_eq!(r.exit_code(), 2);
    assert_eq!(r.anchored_entries, 20);
}

#[test]
fn local_bundles_verify_unanchored() {
    let b = bundle_named("local.json");
    let r = check(&b, &open_log());
    assert_eq!(r.verdict, Verdict::Unanchored, "{:#?}", r.findings);
    assert_eq!(r.failures().count(), 0);
    assert_eq!(r.bundle_signature, SignatureStatus::Unsigned);
    assert!(r.has(Code::NoAnchors));
    assert_eq!(b.redacted_slots.len(), 1);
    // A pinned log key says the bundle must come from that log, signed.
    assert_fails(&check(&b, &full_trust()), Code::BundleSignature);
}

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

fn small_journal() -> Journal {
    let mut j = Journal::new(None);
    let start =
        r#"{"format":2,"labels":{},"nonce":"00","run_id":"r1","sdk":"t","sdk_version":"0"}"#;
    j.append(
        META,
        Event::Note {
            kind: note::RUN_START.into(),
            data: start.into(),
            payload: vec![],
        },
    )
    .unwrap();
    let bytes = format!(r#"{{"$bytes":"{}"}}"#, base64_encode(b"\x00\x01"));
    for value in [
        Value::from("write to ann@example.com"),
        Value::from(bytes),
        Value::from("plain"),
    ] {
        j.append(
            ROOT,
            Event::ChannelRecv {
                channel: "in".into(),
                value: value.into(),
            },
        )
        .unwrap();
    }
    j.mark_persisted(j.len());
    j
}

#[test]
fn local_bundles_withhold_by_mode() {
    let bytes = small_journal().to_bytes();
    let cases: [(Redact, &[(u64, u8)]); 4] = [
        (Redact::None, &[]),
        (Redact::Binary, &[(2, 0)]),
        (
            Redact::Detectors(vec![crate::redact::Kind::Email]),
            &[(1, 0), (2, 0)],
        ),
        (Redact::All, &[(1, 0), (2, 0), (3, 0)]),
    ];
    for (redact, want) in cases {
        let b = Bundle::local(&bytes, "r1", &redact).unwrap();
        assert_eq!(b.redaction.mode, redact.mode());
        assert_eq!(b.redacted_slots, want, "{redact:?}");
        assert!(b.anchors.is_empty() && b.signature.is_none());
        assert!(b.requested_by.starts_with("local:"));
        let r = check(&b, &open_log());
        assert_eq!(r.verdict, Verdict::Unanchored, "{:#?}", r.findings);
        assert_eq!(r.failures().count(), 0, "{:#?}", r.findings);
        let again = Bundle::from_json(b.to_json().as_bytes()).unwrap();
        assert_eq!(again, b);
    }
    assert!(
        Bundle::local(&bytes, "r2", &Redact::None).is_err(),
        "run id must match"
    );
}

#[test]
fn redaction_never_assumes_an_unread_slot_is_clean() {
    let image = r#"{"type":"base64","media_type":"image/png","data":"QUJD"}"#;
    let deep = format!("{}{image}{}", "[".repeat(70), "]".repeat(70));
    for r in [
        Redact::Binary,
        Redact::Detectors(vec![crate::redact::Kind::Email]),
    ] {
        assert!(r.withholds(deep.as_bytes()), "{r:?}: nested past 64 levels");
        assert!(r.withholds(b"[1, 2"), "{r:?}: not read to its end");
        assert!(!r.withholds(b"[1, 2]"), "{r:?}");
        assert!(!r.withholds(b"plain words"), "{r:?}");
    }
}

#[test]
fn withholding_more_keeps_anchors_valid() {
    let mut b = bundle();
    let changed = b.withhold(&[(4, 1)]).unwrap();
    assert_eq!(changed, [(4, 1)]);
    assert!(
        b.signature.is_none(),
        "the old signature no longer covers it"
    );
    assert!(b.redacted_slots.contains(&(4, 1)));
    // Unsigned now, so verified without the log key: the anchors, and the
    // witnesses that vouch for them, are untouched.
    let r = check(&b, &open_log());
    assert_eq!(r.verdict, Verdict::Verified, "{:#?}", r.findings);
    // The ref in entry 12 now reads as withheld too.
    let rec = &b.records[12];
    assert_eq!(rec.slots[1].state, crate::journal::SlotState::Ref);
    assert!(rec.slots[1].text.is_none());
}

#[test]
fn directory_form_needs_its_journal() {
    let mut b = bundle_named("local.json");
    let journal = b.into_directory_form();
    let json = b.to_json();
    let mut read = Bundle::from_json(json.as_bytes()).unwrap();
    assert!(read.journal.bytes.is_empty());
    assert_fails(&check(&read, &full_trust()), Code::JournalMissing);
    assert!(read.attach_journal(b"not it".to_vec()).is_err());
    read.attach_journal(journal).unwrap();
    assert_eq!(check(&read, &open_log()).verdict, Verdict::Unanchored);
    let bad = json.replace(DIRECTORY_JOURNAL_FILE, "../journal");
    assert!(Bundle::from_json(bad.as_bytes()).is_err());
}

// ---------------------------------------------------------------------------
// The adversarial set (design section 9), and every other code
// ---------------------------------------------------------------------------

#[test]
fn self_signed_tsa_is_not_trusted() {
    let rogue = crate::json::Json::parse_bytes(&fixture("rogue.json")).unwrap();
    let certs = rogue.get("certs_pem").and_then(|c| c.as_str()).unwrap();
    let mut b = unsigned(bundle());
    for a in &mut b.anchors {
        let token = rogue
            .get("tokens")
            .and_then(|t| t.get(&a.seq.to_string()))
            .and_then(|t| t.as_str())
            .unwrap();
        let token = crate::encoding::base64_decode(token).unwrap();
        a.witnesses = ["a", "b"]
            .iter()
            .map(|x| Witness::Rfc3161 {
                tsa: format!("https://tsa-{x}.fixture.example/tsr"),
                operator: format!("Fixture TSA {}", x.to_uppercase()),
                token: token.clone(),
                certs_pem: certs.into(),
            })
            .collect();
    }
    let r = check(&b, &open_log());
    assert_eq!(r.verdict, Verdict::Unanchored, "{:#?}", r.findings);
    assert!(r.has(Code::TsaUntrusted));
    assert!(r.anchors.iter().all(|a| a.trusted_operators.is_empty()));
}

#[test]
fn swapped_witness_key_is_not_trusted() {
    let mut policy = full_trust();
    policy.tsa_roots.clear();
    policy.witness_keys = vec![witness_key("witness-wrong.vkey")];
    policy.min_operators = 1;
    let r = check(&bundle(), &policy);
    assert_eq!(r.verdict, Verdict::Unanchored, "{:#?}", r.findings);
    assert!(r.has(Code::CosignatureUntrusted));
}

#[test]
fn forged_cosignature_from_a_pinned_key_fails() {
    let mut b = unsigned(bundle());
    let Some(Witness::Cosignature { line, .. }) = b.anchors[0].witnesses.last_mut() else {
        panic!("the fixture ends with a cosignature");
    };
    // Flip a bit of the signature: same name and key id, bad signature.
    let (prefix, sig) = line.rsplit_once(' ').unwrap();
    let mut raw = crate::encoding::base64_decode(sig).unwrap();
    *raw.last_mut().unwrap() ^= 1;
    *line = format!("{prefix} {}", base64_encode(&raw));
    assert_fails(&check(&b, &full_trust()), Code::CosignatureInvalid);
}

#[test]
fn omitted_anchor_is_caught_by_the_full_log() {
    let log = || AnchorLog::from_json(&fixture("log.json")).unwrap();
    // The complete bundle passes the full-log audit.
    let r = check_audit(&bundle(), &full_trust(), &with_log(log()));
    assert_eq!(r.verdict, Verdict::Verified, "{:#?}", r.findings);
    assert_eq!(r.log_leaves_checked, Some(11));
    // Hiding the last anchor: on its own the bundle still looks fine...
    let mut b = unsigned(bundle());
    b.anchors.pop();
    let r = check(&b, &open_log());
    assert_eq!(r.verdict, Verdict::Partial { unanchored: 12 });
    // ...and the full log shows the leaf it hid.
    assert_fails(
        &check_audit(&b, &full_trust(), &with_log(log())),
        Code::AnchorOmitted,
    );
    // Hiding a middle anchor breaks the leaf chain even without the log.
    let mut b = unsigned(bundle());
    b.anchors.remove(1);
    assert_fails(&check(&b, &full_trust()), Code::AnchorChain);
    // A log that is not the checkpoint's log.
    let mut wrong = log();
    wrong.leaves[0][20] ^= 1;
    assert_fails(
        &check_audit(&bundle(), &full_trust(), &with_log(wrong)),
        Code::LogMismatch,
    );
    let mut short = log();
    short.leaves.pop();
    assert_fails(
        &check_audit(&bundle(), &full_trust(), &with_log(short)),
        Code::LogMismatch,
    );
}

#[test]
fn entries_and_head_must_match() {
    let mut b = unsigned(bundle());
    b.journal.entries += 1;
    assert_fails(&check(&b, &full_trust()), Code::EntriesMismatch);
    let mut b = unsigned(bundle());
    b.journal.head[0] ^= 1;
    assert_fails(&check(&b, &full_trust()), Code::HeadMismatch);
}

#[test]
fn erased_slot_without_a_note_fails() {
    let j = small_journal();
    let note = ErasureNote::local("test", "");
    let erased = j
        .erase(&EraseSelector::Slots(vec![(3, 0)]), &note, 1)
        .unwrap();
    // With its note it is accounted for.
    let b = Bundle::local(&erased.file, "r1", &Redact::None).unwrap();
    assert_eq!(check(&b, &open_log()).failures().count(), 0);
    // Without it, it is not.
    let mut without_note = erased.journal;
    without_note.truncate(without_note.len() - 1);
    let b = Bundle::local(&without_note.to_bytes(), "r1", &Redact::None).unwrap();
    assert_fails(&check(&b, &full_trust()), Code::UnaccountedErasure);
}

#[test]
fn withheld_set_must_match() {
    let mut b = unsigned(bundle());
    b.redacted_slots.clear();
    assert_fails(&check(&b, &full_trust()), Code::WithheldMismatch);
    let mut b = unsigned(bundle());
    b.redacted_slots.push((30, 0));
    assert_fails(&check(&b, &full_trust()), Code::WithheldMismatch);
}

#[test]
fn altered_records_fail() {
    let mut b = unsigned(bundle());
    b.records[4].slots[2].text = Some("Classify the ticket as resolved.".into());
    assert_fails(&check(&b, &full_trust()), Code::RecordsMismatch);
    let mut b = unsigned(bundle());
    b.records.pop();
    assert_fails(&check(&b, &full_trust()), Code::RecordsMismatch);
}

#[test]
fn trailing_journal_bytes_fail() {
    let mut b = unsigned(bundle());
    b.journal.bytes.extend_from_slice(&[0, 0, 0]);
    assert_fails(&check(&b, &full_trust()), Code::JournalTrailingBytes);
}

#[test]
fn damaged_journals_fail_to_parse() {
    let mut b = unsigned(bundle());
    let n = b.journal.bytes.len();
    b.journal.bytes[n / 2] ^= 0x40;
    let r = check(&b, &full_trust());
    assert_eq!(r.verdict, Verdict::Failed);
    assert!(
        r.has(Code::JournalParse) || r.has(Code::JournalTrailingBytes),
        "{:?}",
        codes(&r)
    );
    let mut b = unsigned(bundle());
    b.journal.bytes = Journal::new(Some(b"k")).to_bytes();
    assert_fails(&check(&b, &full_trust()), Code::JournalParse);
}

#[test]
fn bundle_signature_must_verify_with_the_pinned_key() {
    let mut b = bundle();
    b.generator.push('!');
    assert_fails(&check(&b, &full_trust()), Code::BundleSignature);
    // Unpinned and broken: also a failure.
    assert_fails(&check(&b, &TrustPolicy::default()), Code::BundleSignature);
}

#[test]
fn checkpoint_signatures_must_verify_with_pinned_log_keys() {
    let mut policy = full_trust();
    let other = crate::note::VerifierKey::new(
        "pragmatic/fixture.example",
        crate::note::SignatureType::Ed25519,
        *vkey("witness.vkey").public_key(),
    )
    .unwrap();
    policy.log_keys = vec![other];
    assert_fails(&check(&bundle(), &policy), Code::LogSignature);
}

#[test]
fn run_id_must_match() {
    let mut b = unsigned(bundle());
    b.run_id = "another-run".into();
    assert_fails(&check(&b, &full_trust()), Code::RunIdMismatch);
}

#[test]
fn anchor_proofs_and_digests_are_checked() {
    let mut b = unsigned(bundle());
    b.anchors[0].inclusion_proof[0][0] ^= 1;
    assert_fails(&check(&b, &full_trust()), Code::AnchorInclusion);

    let mut b = unsigned(bundle());
    b.anchors[1].anchor_digest[0] ^= 1;
    let r = check(&b, &full_trust());
    assert_fails(&r, Code::AnchorDigest);
    assert!(
        r.has(Code::TsaImprintMismatch),
        "the tokens stamp the real digest"
    );

    let mut b = unsigned(bundle());
    b.anchors[0].consistency_to_latest[0][0] ^= 1;
    assert_fails(&check(&b, &full_trust()), Code::AnchorConsistency);

    let mut b = unsigned(bundle());
    b.anchors[0].tree_size += 1;
    assert_fails(&check(&b, &full_trust()), Code::AnchorCheckpoint);

    let mut b = unsigned(bundle());
    b.latest_checkpoint = None;
    assert_fails(&check(&b, &full_trust()), Code::AnchorConsistency);
}

#[test]
fn leaves_must_anchor_the_journal() {
    let mut b = unsigned(bundle());
    let mut leaf = Leaf::decode(&b.anchors[0].leaf).unwrap();
    leaf.entries = 7;
    b.anchors[0].leaf = leaf.encode();
    assert_fails(&check(&b, &full_trust()), Code::AnchorHeadMismatch);

    let mut b = unsigned(bundle());
    b.anchors[0].leaf.push(0);
    assert_fails(&check(&b, &full_trust()), Code::AnchorLeaf);
}

#[test]
fn swapped_and_malformed_tokens() {
    let mut b = unsigned(bundle());
    let other = b.anchors[1].witnesses[0].clone();
    b.anchors[0].witnesses[0] = other;
    assert_fails(&check(&b, &full_trust()), Code::TsaImprintMismatch);
    let mut b = unsigned(bundle());
    if let Witness::Rfc3161 { token, .. } = &mut b.anchors[0].witnesses[0] {
        token.truncate(10);
    }
    assert_fails(&check(&b, &full_trust()), Code::WitnessMalformed);
    let mut b = unsigned(bundle());
    if let Witness::Rfc3161 { certs_pem, .. } = &mut b.anchors[0].witnesses[0] {
        certs_pem.insert_str(0, "-----BEGIN PRIVATE KEY-----\n");
    }
    assert_fails(&check(&b, &full_trust()), Code::WitnessMalformed);
}

#[test]
fn witness_logs_detect_forks() {
    let wl = WitnessLog::from_json(&fixture("witness-log.json")).unwrap();
    let r = check_audit(&bundle(), &full_trust(), &with_witness_log(wl.clone()));
    assert_eq!(r.verdict, Verdict::Verified, "{:#?}", r.findings);
    assert!(r
        .checks
        .iter()
        .any(|c| c.step == "11" && c.status == CheckStatus::Pass));
    // With the full log too, every cosigned root is checked against it.
    let both = Audit {
        log: Some(AnchorLog::from_json(&fixture("log.json")).unwrap()),
        witness_logs: vec![wl.clone()],
    };
    assert_eq!(
        check_audit(&bundle(), &full_trust(), &both).verdict,
        Verdict::Verified
    );

    // A root the witness never signed: the history is not the witness's.
    // (Forks the witness did cosign are built in the attacks module.)
    let mut forged = wl.clone();
    let mut lines: Vec<String> = forged.checkpoints[0]
        .body
        .lines()
        .map(str::to_string)
        .collect();
    lines[2] = base64_encode(&[7u8; 32]);
    forged.checkpoints[0].body = format!("{}\n", lines.join("\n"));
    assert_fails(
        &check_audit(&bundle(), &full_trust(), &with_witness_log(forged)),
        Code::WitnessLogUntrusted,
    );

    // A cosigned checkpoint the witness never recorded.
    let mut missing = wl.clone();
    missing.checkpoints.remove(1);
    assert_fails(
        &check_audit(&bundle(), &full_trust(), &with_witness_log(missing)),
        Code::WitnessLogMismatch,
    );

    // A history for another log does not apply: the audit asked for fails.
    let mut other = wl;
    other.origin = "pragmatic/elsewhere".into();
    assert_fails(
        &check_audit(&bundle(), &full_trust(), &with_witness_log(other)),
        Code::WitnessLogOrigin,
    );
}

#[test]
fn unreadable_bundles_fail_with_their_code() {
    let r = EvidenceReport::unreadable(Code::BundleFile, "journal.pragmatic is a FIFO", 2);
    assert_fails(&r, Code::BundleFile);
    assert_eq!(r.exit_code(), 1);
    assert_eq!(r.checks[0].step, "2");
}

#[test]
fn witness_key_validity_windows() {
    let mut policy = full_trust();
    policy.tsa_roots.clear();
    policy.min_operators = 1;
    policy.witness_keys[0].not_after = Some(1_000);
    let r = check(&bundle(), &policy);
    assert_eq!(r.verdict, Verdict::Unanchored);
    assert!(r.has(Code::WitnessKeyExpired));
    policy.witness_keys[0].not_after = Some(u64::MAX);
    assert_eq!(check(&bundle(), &policy).verdict, Verdict::Verified);
}

#[test]
fn every_failure_code_is_exercised_somewhere() {
    // A guard against adding a code without a test: the failure codes the
    // tests in this module and the attacks module assert.
    let tested = [
        Code::BundleJson,
        Code::BundleSchema,
        Code::BundleSignature,
        Code::JournalMissing,
        Code::JournalParse,
        Code::JournalTrailingBytes,
        Code::EntriesMismatch,
        Code::HeadMismatch,
        Code::WithheldMismatch,
        Code::UnaccountedErasure,
        Code::RecordsMismatch,
        Code::RunIdMismatch,
        Code::AnchorLeaf,
        Code::AnchorHeadMismatch,
        Code::AnchorInclusion,
        Code::AnchorCheckpoint,
        Code::AnchorDigest,
        Code::AnchorConsistency,
        Code::AnchorChain,
        Code::LogSignature,
        Code::WitnessMalformed,
        Code::TsaImprintMismatch,
        Code::CosignatureInvalid,
        Code::AnchorOmitted,
        Code::LogMismatch,
        Code::WitnessLogFork,
        Code::WitnessLogMismatch,
        Code::WitnessLogOrigin,
        Code::WitnessLogUntrusted,
        Code::LogUnauditable,
        Code::BundleFile,
    ];
    // Reached only through journals the parser already refuses (a broken
    // chain, a format 1 journal, erasure notes that list missing or still
    // sealed slots), which the journal's own tests cover.
    let elsewhere = [
        Code::JournalFormat,
        Code::Chain,
        Code::ErasureIncomplete,
        Code::InvalidErasureNote,
    ];
    for code in Code::ALL {
        if code.severity() == Severity::Failure {
            assert!(
                tested.contains(code) || elsewhere.contains(code),
                "{code} has no test"
            );
        }
    }
}
