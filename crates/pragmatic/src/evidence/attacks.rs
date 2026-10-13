//! Attacks on anchoring, built end to end: logs, checkpoints, cosignatures
//! and bundles signed here with the test-only signer, so each scenario is
//! exactly the one an operator (or someone in the middle) could build, and
//! the verifier is checked against it rather than against a tampered
//! fixture.
//!
//! Every scenario uses cosigning witnesses only (three operators, each
//! with a pinned key) and no TSAs, so nothing depends on OpenSSL. The same
//! attacks, with real TSAs and both verifiers, are in
//! `tools/test_evidence_attacks.py`.

use std::collections::HashMap;
use std::sync::OnceLock;

use super::*;
use crate::ed25519::test_signing::{public_key, sign};
use crate::journal::{note, Event, Journal, META, ROOT};
use crate::merkle;
use crate::note::{cosignature_v1_message, NoteSignature, SignatureType, VerifierKey};
use crate::sha256::{hmac_sha256, sha256};
use crate::value::Value;

#[allow(unused_imports)]
use crate::encoding::base64_encode;

const ORIGIN: &str = "pragmatic/attack.example";
const RUN: &str = "r1";
/// A time in October 2026, when the scenarios are anchored.
const NOW: u64 = 1_791_900_000;

/// A key with a known seed.
struct Signer {
    name: String,
    seed: [u8; 32],
    kind: SignatureType,
}

impl Signer {
    fn new(name: &str, label: &str, kind: SignatureType) -> Signer {
        Signer {
            name: name.into(),
            seed: sha256(label.as_bytes()),
            kind,
        }
    }

    fn log(label: &str) -> Signer {
        Signer::new(ORIGIN, label, SignatureType::Ed25519)
    }

    fn witness(n: u32) -> Signer {
        let name = format!("witness-{n}.example");
        Signer::new(&name, &name, SignatureType::CosignatureV1)
    }

    fn vkey(&self) -> VerifierKey {
        VerifierKey::new(&self.name, self.kind, public_key(&self.seed)).unwrap()
    }

    fn line(&self, signature: Vec<u8>) -> String {
        NoteSignature {
            name: self.name.clone(),
            key_id: self.vkey().key_id(),
            signature,
        }
        .to_line()
        .unwrap()
    }

    fn note_line(&self, body: &str) -> String {
        self.line(sign(&self.seed, body.as_bytes()).to_vec())
    }

    fn cosignature(&self, body: &str, timestamp: u64) -> Witness {
        let message = cosignature_v1_message(timestamp, body);
        let mut sig = timestamp.to_be_bytes().to_vec();
        sig.extend_from_slice(&sign(&self.seed, message.as_bytes()));
        Witness::Cosignature {
            name: self.name.clone(),
            line: self.line(sig),
        }
    }

    fn witness_key(&self, operator: &str) -> WitnessKey {
        WitnessKey {
            operator: operator.into(),
            key: self.vkey(),
            not_before: None,
            not_after: None,
        }
    }
}

/// An anchor log as design 4.7 defines it.
struct Log {
    origin: String,
    key: Signer,
    leaves: Vec<Vec<u8>>,
    last: HashMap<Vec<u8>, u64>,
}

impl Log {
    fn new(origin: &str, key: Signer) -> Log {
        Log {
            origin: origin.into(),
            key,
            leaves: Vec::new(),
            last: HashMap::new(),
        }
    }

    /// Append a run leaf, chained to the id's previous leaf unless `fresh`.
    fn add(&mut self, id: &[u8], entries: u64, head: Digest, fresh: bool) -> u64 {
        let index = self.leaves.len() as u64;
        let prev = if fresh {
            None
        } else {
            self.last.get(id).copied()
        };
        self.last.insert(id.to_vec(), index);
        self.leaves.push(
            Leaf {
                kind: LEAF_RUN,
                id: id.to_vec(),
                entries,
                head,
                prev_leaf_index: prev,
            }
            .encode(),
        );
        index
    }

    /// Another run's leaf.
    fn other(&mut self, name: &str) -> u64 {
        self.add(name.as_bytes(), 1, sha256(name.as_bytes()), false)
    }

    fn hashes(&self, size: u64) -> Vec<Digest> {
        self.leaves[..size as usize]
            .iter()
            .map(|l| merkle::leaf_hash(l))
            .collect()
    }

    fn body(&self, size: u64) -> String {
        let root = merkle::root(&self.hashes(size));
        format!("{}\n{size}\n{}\n", self.origin, base64_encode(&root))
    }

    fn note(&self, size: u64) -> String {
        let body = self.body(size);
        format!("{body}\n{}\n", self.key.note_line(&body))
    }

    /// The anchor of the leaf at `index` in the checkpoint of `size`.
    fn anchor(&self, seq: u64, size: u64, index: u64, latest: u64, by: &[Witness]) -> Anchor {
        let hashes = self.hashes(latest);
        let body = self.body(size);
        Anchor {
            seq,
            tree_size: size,
            leaf_index: index,
            leaf: self.leaves[index as usize].clone(),
            inclusion_proof: merkle::inclusion_proof(index as usize, &hashes[..size as usize])
                .unwrap(),
            root: merkle::root(&hashes[..size as usize]),
            checkpoint: self.note(size),
            anchor_digest: sha256(body.as_bytes()),
            consistency_to_latest: merkle::consistency_proof(size as usize, &hashes).unwrap(),
            witnesses: by.to_vec(),
        }
    }

    /// The witness's cosigned history of this log at `sizes`.
    fn history(&self, witness: &Signer, sizes: &[u64]) -> WitnessLog {
        let checkpoints = sizes
            .iter()
            .map(|&s| {
                let body = self.body(s);
                let Witness::Cosignature { line, .. } = witness.cosignature(&body, NOW) else {
                    unreachable!()
                };
                crate::note::Note::parse(&format!("{}{line}\n", self.note(s))).unwrap()
            })
            .collect();
        WitnessLog {
            witness: witness.name.clone(),
            origin: self.origin.clone(),
            checkpoints,
        }
    }

    fn full(&self) -> AnchorLog {
        AnchorLog {
            leaves: self.leaves.clone(),
        }
    }
}

/// A run's journal; `amount` is the content of the entry an operator would
/// rewrite.
fn journal(amount: &str) -> Journal {
    let mut j = Journal::new(None);
    let start = format!(
        r#"{{"format":2,"labels":{{}},"nonce":"00","run_id":"{RUN}","sdk":"t","sdk_version":"0"}}"#
    );
    j.append(
        META,
        Event::Note {
            kind: note::RUN_START.into(),
            data: start,
            payload: vec![],
        },
    )
    .unwrap();
    for text in ["invoice 4127", amount, "refund sent"] {
        j.append(
            ROOT,
            Event::ChannelRecv {
                channel: "in".into(),
                value: Value::from(text).into(),
            },
        )
        .unwrap();
    }
    j.mark_persisted(j.len());
    j
}

/// One journal per content for the whole test run: salts are random, so a
/// journal built twice has other commitments and heads.
fn cached(cell: &'static OnceLock<Vec<u8>>, amount: &str) -> Journal {
    let bytes = cell.get_or_init(|| journal(amount).to_bytes());
    Journal::parse(bytes, None).unwrap().journal
}

fn honest() -> Journal {
    static HONEST: OnceLock<Vec<u8>> = OnceLock::new();
    cached(&HONEST, r#"{"amount":"49.00"}"#)
}

fn forged() -> Journal {
    static FORGED: OnceLock<Vec<u8>> = OnceLock::new();
    cached(&FORGED, r#"{"amount":"4900.00"}"#)
}

/// `heads[n]`: the chain head after `n` entries.
fn heads(j: &Journal) -> Vec<Digest> {
    std::iter::once(j.genesis())
        .chain(j.entries().iter().map(|e| e.hash))
        .collect()
}

fn bundle(
    j: &Journal,
    anchors: Vec<Anchor>,
    latest: String,
    anchor_id: Option<[u8; 32]>,
    signer: Option<&Signer>,
) -> Bundle {
    let mut b = Bundle::local(&j.to_bytes(), RUN, &Redact::None).unwrap();
    b.anchors = anchors;
    b.latest_checkpoint = Some(latest);
    b.anchor_id = anchor_id;
    b.independent = true;
    if let Some(k) = signer {
        b.signature = Some(BundleSignature {
            key_id: k.vkey().key_id(),
            public_key: public_key(&k.seed),
            value: sign(&k.seed, &b.signature_message()),
        });
    }
    b
}

/// The log key and three witnesses, each its own operator.
fn trust() -> TrustPolicy {
    TrustPolicy {
        witness_keys: (1..=3)
            .map(|n| Signer::witness(n).witness_key(&format!("op-{n}")))
            .collect(),
        log_keys: vec![Signer::log("log").vkey()],
        ..TrustPolicy::default()
    }
}

fn run(b: &Bundle, policy: &TrustPolicy, audit: Audit) -> EvidenceReport {
    verify_with(b, policy, &NoTsaVerifier, &audit)
}

fn audit(log: Option<AnchorLog>, witness_logs: Vec<WitnessLog>) -> Audit {
    Audit { log, witness_logs }
}

fn codes(r: &EvidenceReport) -> Vec<&'static str> {
    r.findings.iter().map(|f| f.code.as_str()).collect()
}

fn assert_fails(r: &EvidenceReport, code: Code) {
    assert_eq!(r.verdict, Verdict::Failed, "{:?}", codes(r));
    assert!(r.has(code), "expected {code}, got {:?}", codes(r));
}

/// Witnesses 1 and 2 cosign `body` now.
fn two(body: &str) -> Vec<Witness> {
    vec![
        Signer::witness(1).cosignature(body, NOW),
        Signer::witness(2).cosignature(body, NOW + 1),
    ]
}

/// The honest run, anchored at 2 and at 4 entries (all of it) in a log
/// shared with other runs, each batch cosigned by witness 1 as its history
/// records. Returns the log, the run's leaf indexes and the batch sizes.
fn honest_log(id: &[u8]) -> (Log, Vec<u64>, Vec<u64>) {
    let h = heads(&honest());
    let mut log = Log::new(ORIGIN, Signer::log("log"));
    let (mut ours, mut sizes) = (Vec::new(), Vec::new());
    log.other("billing-1");
    ours.push(log.add(id, 2, h[2], false));
    sizes.push(log.leaves.len() as u64);
    log.other("billing-2");
    ours.push(log.add(id, 4, h[4], false));
    sizes.push(log.leaves.len() as u64);
    log.other("billing-3");
    sizes.push(log.leaves.len() as u64);
    (log, ours, sizes)
}

/// The honest bundle of [`honest_log`].
fn honest_bundle(log: &Log, ours: &[u64], sizes: &[u64], anchor_id: Option<[u8; 32]>) -> Bundle {
    let latest = *sizes.last().unwrap();
    let anchors = ours
        .iter()
        .zip(sizes)
        .enumerate()
        .map(|(seq, (&i, &s))| log.anchor(seq as u64, s, i, latest, &two(&log.body(s))))
        .collect();
    bundle(
        &honest(),
        anchors,
        log.note(latest),
        anchor_id,
        Some(&log.key),
    )
}

#[test]
fn the_honest_scenario_verifies_with_every_audit() {
    let (log, ours, sizes) = honest_log(RUN.as_bytes());
    let b = honest_bundle(&log, &ours, &sizes, None);
    let history = log.history(&Signer::witness(1), &sizes);
    let r = run(&b, &trust(), audit(Some(log.full()), vec![history.clone()]));
    assert_eq!(r.verdict, Verdict::Verified, "{:#?}", r.findings);
    assert!(r.failures().next().is_none());
    // Without --log, the history still links through the latest checkpoint.
    let r = run(&b, &trust(), audit(None, vec![history]));
    assert_eq!(r.verdict, Verdict::Verified, "{:#?}", r.findings);
}

/// Finding: with `anchor_run_ids = "hmac"` the bundle chooses `k_run`, so an
/// operator can rewrite an anchored journal and anchor it again as a fresh
/// leaf chain under a new key, where `--log` cannot see the old leaves.
#[test]
fn rekeyed_hmac_anchors_cannot_pass_the_full_log_audit() {
    let k_real = sha256(b"real k_run");
    let k_fake = sha256(b"fresh k_run");
    let scenario = |real: Option<[u8; 32]>, fake: Option<[u8; 32]>| {
        let id = |k: Option<[u8; 32]>| {
            k.map_or(RUN.as_bytes().to_vec(), |k| {
                hmac_sha256(&k, RUN.as_bytes()).to_vec()
            })
        };
        let (mut log, _, mut sizes) = honest_log(&id(real));
        let f = heads(&forged());
        let index = log.add(&id(fake), 4, f[4], true);
        log.other("zeta-7");
        sizes.push(log.leaves.len() as u64);
        let latest = *sizes.last().unwrap();
        let a = log.anchor(0, latest, index, latest, &two(&log.body(latest)));
        let b = bundle(&forged(), vec![a], log.note(latest), fake, Some(&log.key));
        let history = log.history(&Signer::witness(1), &sizes);
        (b, log.full(), history)
    };
    let (b, full, history) = scenario(Some(k_real), Some(k_fake));
    // On its own the bundle is what it claims; the warning says what it
    // cannot show.
    let r = run(&b, &trust(), audit(None, vec![history.clone()]));
    assert_eq!(r.verdict, Verdict::Verified, "{:#?}", r.findings);
    assert!(r.has(Code::AnchorIdUnbound));
    // Asked to rule out hidden anchors, the verifier must not pass it.
    let r = run(&b, &trust(), audit(Some(full), vec![history]));
    assert_fails(&r, Code::LogUnauditable);
    assert!(!r.checks.iter().any(|c| c.step == "11"
        && c.name.starts_with("full log")
        && c.status == CheckStatus::Pass));
    // With plain ids the same rewrite is caught.
    let (b, full, history) = scenario(None, None);
    assert_fails(
        &run(&b, &trust(), audit(Some(full), vec![history])),
        Code::AnchorOmitted,
    );
}

/// The operator forks the log and anchors a rewritten journal in the fork,
/// at tree sizes the witness never cosigned. `fork_origin` renames the
/// fork's origin.
fn fork(fork_origin: &str) -> (Bundle, AnchorLog, WitnessLog) {
    let (honest_log, _, sizes) = honest_log(RUN.as_bytes());
    let history = honest_log.history(&Signer::witness(1), &sizes);
    let f = heads(&forged());
    let mut fork = Log::new(fork_origin, Signer::log("log"));
    fork.leaves.push(honest_log.leaves[0].clone());
    let index = fork.add(RUN.as_bytes(), 4, f[4], true);
    fork.other("filler-0");
    let anchored = fork.leaves.len() as u64;
    while fork.leaves.len() < 8 {
        fork.other(&format!("filler-{}", fork.leaves.len()));
    }
    let latest = fork.leaves.len() as u64;
    // Witnesses 2 and 3 cosign whatever they are shown; witness 1, whose
    // history the auditor holds, is never asked.
    let by = |body: &str| {
        vec![
            Signer::witness(2).cosignature(body, NOW),
            Signer::witness(3).cosignature(body, NOW),
        ]
    };
    let a = fork.anchor(0, anchored, index, latest, &by(&fork.body(anchored)));
    let b = bundle(&forged(), vec![a], fork.note(latest), None, Some(&fork.key));
    assert_ne!(sizes, [anchored, latest]);
    (b, fork.full(), history)
}

#[test]
fn a_fork_at_sizes_the_witness_never_cosigned_is_caught() {
    let (b, full, history) = fork(ORIGIN);
    // Each anchor and checkpoint is well formed and witnessed.
    assert_eq!(
        run(&b, &trust(), Audit::default()).verdict,
        Verdict::Verified
    );
    // With the fork's own leaves, the witness's roots do not match.
    assert_fails(
        &run(
            &b,
            &trust(),
            audit(Some(full.clone()), vec![history.clone()]),
        ),
        Code::WitnessLogFork,
    );
    // Without --log, no tree head links the bundle to what the witness saw.
    assert_fails(
        &run(&b, &trust(), audit(None, vec![history.clone()])),
        Code::WitnessLogMismatch,
    );
    // --log alone audits against the operator's tree head, and a witness
    // history is what shows a fork: the docs say so.
    assert_eq!(
        run(&b, &trust(), audit(Some(full), vec![])).verdict,
        Verdict::Verified
    );
}

#[test]
fn a_fork_under_a_renamed_origin_is_caught() {
    let (b, _, history) = fork(&format!("{ORIGIN}-mirror"));
    // The pinned log key is named for its origin.
    assert_fails(&run(&b, &trust(), Audit::default()), Code::LogSignature);
    // Without the log key, the requested witness-log audit does not apply,
    // and that is a failure, not a skipped step.
    let mut no_log_key = trust();
    no_log_key.log_keys.clear();
    let mut unsigned = b.clone();
    unsigned.signature = None;
    let r = run(&unsigned, &no_log_key, audit(None, vec![history]));
    assert_fails(&r, Code::WitnessLogOrigin);
}

#[test]
fn a_witness_log_must_be_cosigned_by_the_pinned_witness() {
    let (log, ours, sizes) = honest_log(RUN.as_bytes());
    let b = honest_bundle(&log, &ours, &sizes, None);
    let real = log.history(&Signer::witness(1), &sizes);
    // A history whoever handed it over wrote: lines that verify with nothing.
    let mut bogus = real.clone();
    for n in &mut bogus.checkpoints {
        n.signatures[1] = NoteSignature::parse_line("\u{2014} witness-1.example AAAAAAE=").unwrap();
    }
    let r = run(&b, &trust(), audit(None, vec![bogus]));
    assert_fails(&r, Code::WitnessLogUntrusted);
    assert!(!r
        .checks
        .iter()
        .any(|c| c.step == "11" && c.status == CheckStatus::Pass));
    // A history signed by another key under the witness's name.
    let impostor = Signer::new(
        "witness-1.example",
        "impostor",
        SignatureType::CosignatureV1,
    );
    let r = run(
        &b,
        &trust(),
        audit(None, vec![log.history(&impostor, &sizes)]),
    );
    assert_fails(&r, Code::WitnessLogUntrusted);
    // A history of a witness no key is pinned for.
    let mut policy = trust();
    policy
        .witness_keys
        .retain(|k| k.key.name() != "witness-1.example");
    let r = run(&b, &policy, audit(None, vec![real.clone()]));
    assert_fails(&r, Code::WitnessLogUntrusted);
    // An empty history vouches for nothing.
    let mut empty = real;
    empty.checkpoints.clear();
    assert_fails(
        &run(&b, &trust(), audit(None, vec![empty])),
        Code::WitnessLogUntrusted,
    );
}

#[test]
fn a_witness_ahead_of_the_bundle_needs_a_link() {
    let (mut log, ours, sizes) = honest_log(RUN.as_bytes());
    let b = honest_bundle(&log, &ours, &sizes, None);
    // The log grows after the bundle was made, and the witness cosigns it.
    log.other("later-1");
    let later = log.leaves.len() as u64;
    let w1 = Signer::witness(1);
    // The history includes the bundle's latest checkpoint: linked.
    let mut with_latest = sizes.clone();
    with_latest.push(later);
    let r = run(
        &b,
        &trust(),
        audit(None, vec![log.history(&w1, &with_latest)]),
    );
    assert_eq!(r.verdict, Verdict::Verified, "{:#?}", r.findings);
    // It does not: the bundle cannot show it is on the witness's chain...
    let skipped = [sizes[0], sizes[1], later];
    assert_fails(
        &run(&b, &trust(), audit(None, vec![log.history(&w1, &skipped)])),
        Code::WitnessLogMismatch,
    );
    // ...until a log that reaches the witness's tree is given.
    let r = run(
        &b,
        &trust(),
        audit(Some(log.full()), vec![log.history(&w1, &skipped)]),
    );
    assert_eq!(r.verdict, Verdict::Verified, "{:#?}", r.findings);
}

/// Finding: one compromised witness backdated the reported time on its own.
#[test]
fn one_operator_cannot_backdate_an_anchor() {
    let mut log = Log::new(ORIGIN, Signer::log("log"));
    log.other("billing-1");
    let index = log.add(RUN.as_bytes(), 4, heads(&honest())[4], false);
    let size = log.leaves.len() as u64;
    let body = log.body(size);
    let backdated = 1_577_836_800; // 2020-01-01
    let by = vec![
        Signer::witness(1).cosignature(&body, backdated),
        Signer::witness(2).cosignature(&body, NOW),
        Signer::witness(3).cosignature(&body, NOW + 60),
    ];
    let b = bundle(
        &honest(),
        vec![log.anchor(0, size, index, size, &by)],
        log.note(size),
        None,
        Some(&log.key),
    );
    let r = run(&b, &trust(), Audit::default());
    assert_eq!(r.verdict, Verdict::Verified, "{:#?}", r.findings);
    let t = r.anchors[0].earliest.unwrap();
    assert_eq!(
        t.unix,
        NOW as i64,
        "the second operator's time: {}",
        t.rfc3339()
    );
    // With three operators required, the third's time.
    let mut three = trust();
    three.min_operators = 3;
    let r = run(&b, &three, Audit::default());
    assert_eq!(r.anchors[0].earliest.unwrap().unix, NOW as i64 + 60);
    // With one, the earliest of all.
    three.min_operators = 1;
    let r = run(&b, &three, Audit::default());
    assert_eq!(r.anchors[0].earliest.unwrap().unix, backdated as i64);
}

/// Finding: a genuine anchor of a PUT-created run (0 entries) commits only
/// to the genesis head every unkeyed journal shares.
#[test]
fn a_zero_entry_anchor_anchors_nothing() {
    let mut log = Log::new(ORIGIN, Signer::log("log"));
    log.other("billing-1");
    let genesis = forged().genesis();
    assert_eq!(genesis, honest().genesis());
    let index = log.add(RUN.as_bytes(), 0, genesis, false);
    let size = log.leaves.len() as u64;
    let b = bundle(
        &forged(),
        vec![log.anchor(0, size, index, size, &two(&log.body(size)))],
        log.note(size),
        None,
        Some(&log.key),
    );
    let r = run(&b, &trust(), Audit::default());
    assert_eq!(r.verdict, Verdict::Unanchored, "{:#?}", r.findings);
    assert_eq!(r.exit_code(), 3);
    assert_eq!(r.anchored_entries, 0);
}

/// Finding: with the log key pinned, a stripped or foreign bundle signature
/// left the bundle's unsigned fields open to anyone.
#[test]
fn a_pinned_log_key_requires_its_bundle_signature() {
    let (log, ours, sizes) = honest_log(RUN.as_bytes());
    let b = honest_bundle(&log, &ours, &sizes, None);
    assert_eq!(
        run(&b, &trust(), Audit::default()).verdict,
        Verdict::Verified
    );
    let mut stripped = b.clone();
    stripped.signature = None;
    stripped.requested_by = "tok_regulator".into();
    let r = run(&stripped, &trust(), Audit::default());
    assert_fails(&r, Code::BundleSignature);
    assert_eq!(r.bundle_signature, SignatureStatus::Unsigned);
    // Re-signed by someone else's key.
    let mitm = Signer::log("someone else");
    let mut resigned = stripped.clone();
    resigned.signature = Some(BundleSignature {
        key_id: mitm.vkey().key_id(),
        public_key: public_key(&mitm.seed),
        value: sign(&mitm.seed, &stripped.signature_message()),
    });
    assert_fails(
        &run(&resigned, &trust(), Audit::default()),
        Code::BundleSignature,
    );
    // Without a pinned log key both read as before: unsigned, or asserted.
    let mut open = trust();
    open.log_keys.clear();
    let r = run(&stripped, &open, Audit::default());
    assert_eq!(r.verdict, Verdict::Verified, "{:#?}", r.findings);
    assert!(r.has(Code::Unsigned));
    let r = run(&resigned, &open, Audit::default());
    assert_eq!(r.verdict, Verdict::Verified);
    assert!(r.has(Code::OperatorAsserted));
}

/// A log built by someone without the log key, for a rewritten journal,
/// witnessed by parties that cosign what they are shown.
#[test]
fn a_log_built_without_the_log_key_fails_against_the_pinned_key() {
    let mitm = Signer::log("someone else");
    let mut log = Log::new(ORIGIN, mitm);
    log.other("billing-1");
    let index = log.add(RUN.as_bytes(), 4, heads(&forged())[4], false);
    let size = log.leaves.len() as u64;
    let b = bundle(
        &forged(),
        vec![log.anchor(0, size, index, size, &two(&log.body(size)))],
        log.note(size),
        None,
        Some(&log.key),
    );
    let r = run(&b, &trust(), Audit::default());
    assert_fails(&r, Code::LogSignature);
}
