//! Verifying a bundle (design 5.2 and 5.3).
//!
//! [`verify`] runs every check in the order of design 5.3 and collects
//! every finding rather than stopping at the first, so a report shows all
//! that is wrong with a bundle. Each finding has a stable [`Code`]; codes
//! of severity [`Severity::Failure`] are integrity failures and make the
//! verdict [`Verdict::Failed`]. Witnesses that cannot be trusted are not
//! failures: they simply do not count towards independence, and the verdict
//! says how much of the journal (if any) is independently anchored.
//!
//! Trust comes only from the [`TrustPolicy`]: pinned TSA roots, pinned
//! witness keys and pinned log keys. The operator a witness counts for is
//! the operator the *verifier* assigned to the root or key that verified
//! it, never the operator the bundle names, so a bundle cannot make one
//! TSA count twice by calling it two names.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use crate::ed25519;
use crate::journal::{Journal, FORMAT as JOURNAL_FORMAT};
use crate::merkle;
use crate::note::{self, Checkpoint, Note, NoteSignature, VerifierKey};
use crate::sha256::{hex, sha256, Digest};
use crate::tsp;

use super::build::withheld_slots;
use super::leaf::{leaf_id, AnchorLog, Leaf, WitnessLog, LEAF_RUN};
use super::{Anchor, Bundle, BundleError, JournalEncoding, Record, Witness};

/// Operators that are one company under two names (design 4.7): Entrust's
/// public time-stamping is run by Sectigo, and QuoVadis EU belongs to
/// DigiCert. Names are compared after [`normalize_operator`].
pub const DEFAULT_OPERATOR_ALIASES: [(&str, &str); 2] =
    [("entrust", "sectigo"), ("quovadis-eu", "digicert")];

/// An operator name for comparison: lower case, with runs of white space
/// and underscores turned into one `-` (`QuoVadis EU` is `quovadis-eu`).
pub fn normalize_operator(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut gap = false;
    for c in name.trim().chars() {
        if c.is_whitespace() || c == '_' {
            gap = true;
            continue;
        }
        if gap && !out.is_empty() {
            out.push('-');
        }
        gap = false;
        out.extend(c.to_lowercase());
    }
    out
}

// ---------------------------------------------------------------------------
// Trust inputs
// ---------------------------------------------------------------------------

/// A pinned TSA root: a PEM file of one or more root certificates, and the
/// operator every token it verifies counts for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TsaRoot {
    pub operator: String,
    pub path: PathBuf,
}

/// A pinned witness key and the operator it counts for. A key may carry a
/// validity window (Unix seconds): a cosignature timestamped outside it is
/// not trusted. The hosted Pragmatic Witness keys built into the CLI use
/// windows; keys given on the command line normally do not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessKey {
    pub operator: String,
    pub key: VerifierKey,
    pub not_before: Option<u64>,
    pub not_after: Option<u64>,
}

/// Everything the verifier trusts (design 5.2). Nothing in a bundle is
/// ever a trust anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustPolicy {
    /// Pinned TSA roots (`--tsa-roots`).
    pub tsa_roots: Vec<TsaRoot>,
    /// Pinned witness keys (`--witness-key`, plus built-in hosted keys).
    pub witness_keys: Vec<WitnessKey>,
    /// Pinned log keys (`--log-key`): the server's checkpoint key, which
    /// also signs bundles. Without one, both signatures are reported as
    /// operator-asserted.
    pub log_keys: Vec<VerifierKey>,
    /// Distinct trusted operators an anchor needs to count (default 2).
    pub min_operators: usize,
    /// Operator names that stand for the same operator, `(alias, name)`.
    pub operator_aliases: Vec<(String, String)>,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        TrustPolicy {
            tsa_roots: Vec::new(),
            witness_keys: Vec::new(),
            log_keys: Vec::new(),
            min_operators: 2,
            operator_aliases: DEFAULT_OPERATOR_ALIASES
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
        }
    }
}

impl TrustPolicy {
    /// The canonical operator for `name`: normalized, then aliased.
    pub fn operator(&self, name: &str) -> String {
        let n = normalize_operator(name);
        self.operator_aliases
            .iter()
            .find(|(alias, _)| normalize_operator(alias) == n)
            .map_or(n, |(_, to)| normalize_operator(to))
    }
}

/// Optional full-log audits (design 5.3 step 11).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Audit {
    /// The full anchor log (`--log`).
    pub log: Option<AnchorLog>,
    /// Witnesses' cosigned histories (`--witness-log`).
    pub witness_logs: Vec<WitnessLog>,
}

/// One RFC 3161 signature check, handed to a [`TsaVerifier`].
#[derive(Clone, Copy, Debug)]
pub struct TsaCheck<'a> {
    /// A number unique within one verification, for naming files.
    pub index: usize,
    /// The token (DER `ContentInfo`).
    pub token: &'a [u8],
    /// The digest the token must time-stamp (the anchor digest).
    pub digest: &'a Digest,
    /// The bundle's certificates, untrusted intermediates only. Already
    /// checked to be PEM certificate blocks with canonical base64.
    pub certs_pem: &'a str,
    /// The one pinned root file to verify against.
    pub root: &'a Path,
    /// The time to validate certificates at: the token's `genTime` plus
    /// one second (`-attime`), so an expired TSA certificate that was valid
    /// when it signed still verifies.
    pub at_time: i64,
}

/// What a [`TsaVerifier`] concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TsaResult {
    /// The signature verifies and chains to the root.
    Verified,
    /// It does not verify against this root.
    Rejected(String),
    /// It could not be checked at all (no OpenSSL, say). No further roots
    /// are tried.
    Unavailable(String),
}

/// Checks RFC 3161 token signatures. The core never runs processes, so the
/// CLI supplies an implementation backed by `openssl ts -verify`.
pub trait TsaVerifier {
    fn verify(&self, check: &TsaCheck<'_>) -> TsaResult;
}

/// A [`TsaVerifier`] that checks nothing: every token is reported as
/// unchecked, so TSA witnesses never count.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoTsaVerifier;

impl TsaVerifier for NoTsaVerifier {
    fn verify(&self, _: &TsaCheck<'_>) -> TsaResult {
        TsaResult::Unavailable("no RFC 3161 verifier is available".into())
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// How serious a finding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Integrity failure: the verdict is `FAILED`.
    Failure,
    /// Something did not count (an untrusted witness) or looks odd.
    Warning,
    /// For the record.
    Info,
}

macro_rules! codes {
    ($($variant:ident = $name:literal, $sev:ident;)*) => {
        /// A finding's stable identifier, printed by the CLI and matched by
        /// tests and scripts.
        #[non_exhaustive]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum Code { $($variant,)* }

        impl Code {
            /// The code's text, such as `head_mismatch`.
            pub fn as_str(self) -> &'static str {
                match self { $(Code::$variant => $name,)* }
            }

            /// Whether findings with this code fail the bundle.
            pub fn severity(self) -> Severity {
                match self { $(Code::$variant => Severity::$sev,)* }
            }

            /// Every code.
            pub const ALL: &'static [Code] = &[$(Code::$variant,)*];
        }
    };
}

codes! {
    BundleJson = "bundle_json", Failure;
    BundleSchema = "bundle_schema", Failure;
    BundleSignature = "bundle_signature", Failure;
    JournalMissing = "journal_missing", Failure;
    JournalParse = "journal_parse", Failure;
    JournalFormat = "journal_format", Failure;
    JournalTrailingBytes = "journal_trailing_bytes", Failure;
    EntriesMismatch = "entries_mismatch", Failure;
    HeadMismatch = "head_mismatch", Failure;
    Chain = "chain", Failure;
    WithheldMismatch = "withheld_mismatch", Failure;
    UnaccountedErasure = "unaccounted_erasure", Failure;
    ErasureIncomplete = "erasure_incomplete", Failure;
    InvalidErasureNote = "invalid_erasure_note", Failure;
    RecordsMismatch = "records_mismatch", Failure;
    RunIdMismatch = "run_id_mismatch", Failure;
    AnchorLeaf = "anchor_leaf", Failure;
    AnchorHeadMismatch = "anchor_head_mismatch", Failure;
    AnchorInclusion = "anchor_inclusion", Failure;
    AnchorCheckpoint = "anchor_checkpoint", Failure;
    AnchorDigest = "anchor_digest", Failure;
    AnchorConsistency = "anchor_consistency", Failure;
    AnchorChain = "anchor_chain", Failure;
    LogSignature = "log_signature", Failure;
    WitnessMalformed = "witness_malformed", Failure;
    TsaImprintMismatch = "tsa_imprint_mismatch", Failure;
    CosignatureInvalid = "cosignature_invalid", Failure;
    AnchorOmitted = "anchor_omitted", Failure;
    LogMismatch = "log_mismatch", Failure;
    WitnessLogFork = "witness_log_fork", Failure;
    WitnessLogMismatch = "witness_log_mismatch", Failure;
    TsaUntrusted = "tsa_untrusted", Warning;
    TsaUnchecked = "tsa_unchecked", Warning;
    CosignatureUntrusted = "cosignature_untrusted", Warning;
    WitnessKeyExpired = "witness_key_expired", Warning;
    OperatorMismatch = "operator_mismatch", Warning;
    LogNewer = "log_newer", Warning;
    WitnessLogOrigin = "witness_log_origin", Warning;
    Unsigned = "unsigned", Info;
    OperatorAsserted = "operator_asserted", Info;
    NoAnchors = "no_anchors", Info;
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub code: Code,
    pub message: String,
}

impl Finding {
    pub fn severity(&self) -> Severity {
        self.code.severity()
    }
}

/// The outcome of one step of the procedure, for printing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Fail,
    /// Not run, because an earlier step failed or there was nothing to
    /// check.
    Skipped,
    /// Ran; the result is information rather than pass or fail.
    Info,
}

/// One line of the step-by-step report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    /// The step of design 5.3 (`"1"` to `"11"`).
    pub step: &'static str,
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

/// Whether a signature was checked against a pinned key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureStatus {
    /// It verifies with this pinned key.
    Verified { key: String },
    /// It is self-consistent but no pinned key covers it, so it says only
    /// what the operator asserts.
    OperatorAsserted,
    /// There is no signature.
    Unsigned,
    /// It does not verify.
    Invalid,
}

/// How far a witness can be trusted (design 5.3 step 9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessClass {
    /// Verified against a root or key the verifier pinned.
    Trusted,
    /// Not verified against anything the verifier pinned.
    SelfAsserted,
    /// The log's own signature: proves nothing against the operator.
    OperatorControlled,
}

impl WitnessClass {
    pub fn as_str(self) -> &'static str {
        match self {
            WitnessClass::Trusted => "trusted",
            WitnessClass::SelfAsserted => "self-asserted",
            WitnessClass::OperatorControlled => "operator-controlled",
        }
    }
}

/// A time read from a signed structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignedTime {
    pub unix: i64,
    pub nanos: u32,
}

impl SignedTime {
    pub fn rfc3339(&self) -> String {
        super::time::rfc3339(self.unix, self.nanos)
    }
}

/// One witness of one anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessReport {
    /// `rfc3161`, `cosignature` or `server-ed25519`.
    pub kind: &'static str,
    /// The TSA URL or cosigner name, as the bundle gives it (untrusted
    /// text: escape before display).
    pub label: String,
    /// The operator the bundle names, if any (untrusted text).
    pub claimed_operator: Option<String>,
    /// The operator the verifier counts it for, when trusted.
    pub operator: Option<String>,
    pub class: WitnessClass,
    /// The signed time: `genTime` plus accuracy for a TSA, the timestamp
    /// for a cosignature.
    pub time: Option<SignedTime>,
    /// Why it is not trusted, when it is not.
    pub code: Option<Code>,
    pub detail: String,
}

/// One anchor's result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorReport {
    pub seq: u64,
    /// The journal prefix the anchor commits to (0 when the leaf is
    /// unreadable).
    pub entries: u64,
    pub tree_size: u64,
    pub leaf_index: u64,
    /// True when every integrity check of this anchor passed.
    pub sound: bool,
    pub witnesses: Vec<WitnessReport>,
    /// Distinct trusted operators, canonical names, sorted.
    pub trusted_operators: Vec<String>,
    /// Sound and witnessed by at least `min_operators` trusted operators.
    pub independent: bool,
    /// The earliest trusted witness time: the journal prefix existed no
    /// later than this.
    pub earliest: Option<SignedTime>,
}

/// The verdict and its exit code (design 5.3 step 10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The whole journal is independently anchored. Exit 0.
    Verified,
    /// A prefix is independently anchored; `unanchored` entries after it
    /// are not. Exit 2.
    Partial { unanchored: u64 },
    /// No anchor has enough trusted operators. Exit 3.
    Unanchored,
    /// An integrity check failed. Exit 1.
    Failed,
}

impl Verdict {
    pub fn exit_code(self) -> u8 {
        match self {
            Verdict::Verified => 0,
            Verdict::Failed => 1,
            Verdict::Partial { .. } => 2,
            Verdict::Unanchored => 3,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Verdict::Verified => "VERIFIED",
            Verdict::Partial { .. } => "VERIFIED (PARTIAL)",
            Verdict::Unanchored => "UNANCHORED",
            Verdict::Failed => "FAILED",
        }
    }
}

/// Everything verification found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceReport {
    pub verdict: Verdict,
    /// The bundle's run id (untrusted text until the checks pass).
    pub run_id: String,
    /// Entries in the bundle's journal (0 if it did not parse).
    pub entries: u64,
    /// The longest independently anchored prefix.
    pub anchored_entries: u64,
    pub min_operators: usize,
    pub bundle_signature: SignatureStatus,
    /// The step-by-step results.
    pub checks: Vec<Check>,
    /// Every finding, in the order found.
    pub findings: Vec<Finding>,
    pub anchors: Vec<AnchorReport>,
    /// Leaves of the full log checked with `--log`, if one was given.
    pub log_leaves_checked: Option<u64>,
}

impl EvidenceReport {
    pub fn exit_code(&self) -> u8 {
        self.verdict.exit_code()
    }

    /// True if a finding has this code.
    pub fn has(&self, code: Code) -> bool {
        self.findings.iter().any(|f| f.code == code)
    }

    /// The integrity failures.
    pub fn failures(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity() == Severity::Failure)
    }

    fn failed(run_id: String, code: Code, message: String, min_operators: usize) -> Self {
        EvidenceReport {
            verdict: Verdict::Failed,
            run_id,
            entries: 0,
            anchored_entries: 0,
            min_operators,
            bundle_signature: SignatureStatus::Unsigned,
            checks: vec![Check {
                step: "1",
                name: "strict JSON, known keys",
                status: CheckStatus::Fail,
                detail: message.clone(),
            }],
            findings: vec![Finding { code, message }],
            anchors: Vec::new(),
            log_leaves_checked: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Verify a bundle against `policy`, without full-log audits.
pub fn verify(bundle: &Bundle, policy: &TrustPolicy, tsa: &dyn TsaVerifier) -> EvidenceReport {
    verify_with(bundle, policy, tsa, &Audit::default())
}

/// Read and verify a bundle file (an inline bundle; a directory bundle is
/// read with [`Bundle::from_json`] and [`Bundle::attach_journal`] first).
/// A file that is not a bundle gives a `FAILED` report with code
/// `bundle_json` or `bundle_schema`, and no bundle.
pub fn verify_bytes(
    bytes: &[u8],
    policy: &TrustPolicy,
    tsa: &dyn TsaVerifier,
    audit: &Audit,
) -> (Option<Bundle>, EvidenceReport) {
    match Bundle::from_json(bytes) {
        Ok(bundle) => {
            let report = verify_with(&bundle, policy, tsa, audit);
            (Some(bundle), report)
        }
        Err(e) => {
            let (code, msg) = match &e {
                BundleError::Json(_) => (Code::BundleJson, e.to_string()),
                BundleError::Schema(_) => (Code::BundleSchema, e.to_string()),
            };
            let report = EvidenceReport::failed(String::new(), code, msg, policy.min_operators);
            (None, report)
        }
    }
}

/// Verify a bundle against `policy`, with the full-log audits in `audit`.
pub fn verify_with(
    bundle: &Bundle,
    policy: &TrustPolicy,
    tsa: &dyn TsaVerifier,
    audit: &Audit,
) -> EvidenceReport {
    let mut v = Verifier {
        bundle,
        policy,
        tsa,
        audit,
        report: EvidenceReport {
            verdict: Verdict::Failed,
            run_id: bundle.run_id.clone(),
            entries: 0,
            anchored_entries: 0,
            min_operators: policy.min_operators,
            bundle_signature: SignatureStatus::Unsigned,
            checks: Vec::new(),
            findings: Vec::new(),
            anchors: Vec::new(),
            log_leaves_checked: None,
        },
        tsa_index: 0,
    };
    v.run();
    v.report
}

// ---------------------------------------------------------------------------
// The procedure
// ---------------------------------------------------------------------------

struct Verifier<'a> {
    bundle: &'a Bundle,
    policy: &'a TrustPolicy,
    tsa: &'a dyn TsaVerifier,
    audit: &'a Audit,
    report: EvidenceReport,
    tsa_index: usize,
}

/// A parsed checkpoint note.
struct ParsedCheckpoint {
    note: Note,
    checkpoint: Checkpoint,
}

fn parse_checkpoint(text: &str) -> Result<ParsedCheckpoint, String> {
    let note = Note::parse(text).map_err(|e| e.to_string())?;
    let checkpoint = Checkpoint::parse(&note.body).map_err(|e| e.to_string())?;
    Ok(ParsedCheckpoint { note, checkpoint })
}

impl Verifier<'_> {
    fn finding(&mut self, code: Code, message: impl Into<String>) {
        self.report.findings.push(Finding {
            code,
            message: message.into(),
        });
    }

    fn check(
        &mut self,
        step: &'static str,
        name: &'static str,
        status: CheckStatus,
        detail: impl Into<String>,
    ) {
        self.report.checks.push(Check {
            step,
            name,
            status,
            detail: detail.into(),
        });
    }

    /// Record a pass or a failure with `code` for one step.
    fn outcome(
        &mut self,
        step: &'static str,
        name: &'static str,
        failure: Option<(Code, String)>,
        pass: impl Into<String>,
    ) {
        match failure {
            None => self.check(step, name, CheckStatus::Pass, pass),
            Some((code, msg)) => {
                self.check(step, name, CheckStatus::Fail, msg.clone());
                self.finding(code, msg);
            }
        }
    }

    fn run(&mut self) {
        self.check(
            "1",
            "strict JSON, known keys",
            CheckStatus::Pass,
            "the bundle is strict JSON with exactly the keys of pragmatic-evidence/1",
        );
        self.bundle_signature();
        let Some(journal) = self.journal() else {
            self.skip_rest("the journal could not be read");
            self.report.verdict = Verdict::Failed;
            return;
        };
        self.report.entries = journal.len();
        self.chain(&journal);
        self.withheld(&journal);
        self.erasures(&journal);
        self.records(&journal);
        self.run_start(&journal);
        let latest = self.anchors(&journal);
        self.full_log(&journal, latest.as_ref());
        self.witness_logs(latest.as_ref());
        self.verdict(&journal);
        // Steps are reported in the order of design 5.3, whatever order
        // they had to run in (the verdict needs the log audits).
        self.report
            .checks
            .sort_by_key(|c| c.step.parse::<u32>().unwrap_or(u32::MAX));
    }

    fn skip_rest(&mut self, why: &str) {
        for (step, name) in [
            ("3", "chain"),
            ("4", "withheld slots"),
            ("5", "erasures accounted for"),
            ("6", "records equal the journal"),
            ("7", "run id"),
            ("8", "anchors"),
        ] {
            self.check(step, name, CheckStatus::Skipped, why);
        }
    }

    // -- step 1: the bundle signature ---------------------------------------

    fn bundle_signature(&mut self) {
        let Some(sig) = &self.bundle.signature else {
            self.report.bundle_signature = SignatureStatus::Unsigned;
            self.check("1", "bundle signature", CheckStatus::Info, "unsigned");
            self.finding(Code::Unsigned, "the bundle is not signed");
            return;
        };
        let message = self.bundle.signature_message();
        let pinned = self
            .policy
            .log_keys
            .iter()
            .find(|k| k.public_key() == &sig.public_key);
        let valid = ed25519::verify(&sig.public_key, &message, &sig.value);
        match (pinned, valid) {
            (Some(key), true) if key.key_id() == sig.key_id => {
                let name = key.name().to_string();
                self.check(
                    "1",
                    "bundle signature",
                    CheckStatus::Pass,
                    format!("verified with the pinned log key {name}"),
                );
                self.report.bundle_signature = SignatureStatus::Verified { key: name };
            }
            (Some(_), _) => {
                self.report.bundle_signature = SignatureStatus::Invalid;
                self.outcome(
                    "1",
                    "bundle signature",
                    Some((
                        Code::BundleSignature,
                        "the bundle signature does not verify with the pinned log key".into(),
                    )),
                    "",
                );
            }
            (None, true) => {
                self.report.bundle_signature = SignatureStatus::OperatorAsserted;
                self.check(
                    "1",
                    "bundle signature",
                    CheckStatus::Info,
                    "valid, but its key is not pinned: operator-asserted",
                );
                self.finding(
                    Code::OperatorAsserted,
                    "the bundle signature's key is not pinned (pass --log-key)",
                );
            }
            (None, false) => {
                self.report.bundle_signature = SignatureStatus::Invalid;
                self.outcome(
                    "1",
                    "bundle signature",
                    Some((
                        Code::BundleSignature,
                        "the bundle signature does not verify even with the key it names".into(),
                    )),
                    "",
                );
            }
        }
    }

    // -- step 2: the journal ------------------------------------------------

    fn journal(&mut self) -> Option<Journal> {
        const NAME: &str = "journal parses canonically";
        let data = &self.bundle.journal;
        if matches!(data.encoding, JournalEncoding::File { .. }) && data.bytes.is_empty() {
            self.outcome(
                "2",
                NAME,
                Some((
                    Code::JournalMissing,
                    "the bundle references a journal file that was not supplied".into(),
                )),
                "",
            );
            return None;
        }
        let parsed = match Journal::parse_evidence(&data.bytes) {
            Ok(p) => p,
            Err(e) => {
                self.outcome("2", NAME, Some((Code::JournalParse, e.to_string())), "");
                return None;
            }
        };
        let j = parsed.journal;
        if j.format() != JOURNAL_FORMAT {
            self.outcome(
                "2",
                NAME,
                Some((
                    Code::JournalFormat,
                    "evidence journals are format 2; this one is format 1".into(),
                )),
                "",
            );
            return None;
        }
        let mut failed = false;
        if parsed.tail_len != 0 {
            failed = true;
            self.outcome(
                "2",
                NAME,
                Some((
                    Code::JournalTrailingBytes,
                    format!(
                        "{} bytes follow the last complete entry (a bundle's journal ends exactly)",
                        parsed.tail_len
                    ),
                )),
                "",
            );
        }
        if j.len() != data.entries {
            failed = true;
            self.outcome(
                "2",
                "entries and head",
                Some((
                    Code::EntriesMismatch,
                    format!(
                        "the bundle states {} entries; the journal has {}",
                        data.entries,
                        j.len()
                    ),
                )),
                "",
            );
        }
        if j.head() != data.head {
            failed = true;
            self.outcome(
                "2",
                "entries and head",
                Some((
                    Code::HeadMismatch,
                    format!(
                        "the bundle states head {}; the journal's head is {}",
                        hex(&data.head),
                        hex(&j.head())
                    ),
                )),
                "",
            );
        }
        if !failed {
            self.check(
                "2",
                NAME,
                CheckStatus::Pass,
                format!(
                    "{} entries, head {}, no trailing bytes",
                    j.len(),
                    hex(&j.head())
                ),
            );
        }
        Some(j)
    }

    // -- steps 3 to 7 -------------------------------------------------------

    fn chain(&mut self, j: &Journal) {
        let failure = j.verify().err().map(|c| {
            (
                Code::Chain,
                format!("the chain or a commitment fails at cursor {c}"),
            )
        });
        self.outcome(
            "3",
            "chain",
            failure,
            "every chain link, commitment and ref verifies",
        );
    }

    fn withheld(&mut self, j: &Journal) {
        let actual = withheld_slots(j);
        let stated = &self.bundle.redacted_slots;
        let failure = (stated != &actual).then(|| {
            let a: BTreeSet<_> = actual.iter().collect();
            let s: BTreeSet<_> = stated.iter().collect();
            let missing = a.difference(&s).next();
            let extra = s.difference(&a).next();
            let why = match (missing, extra) {
                (Some((c, k)), _) => format!("slot {c}:{k} is withheld but not listed"),
                (_, Some((c, k))) => format!("slot {c}:{k} is listed but not withheld"),
                _ => "the list is not sorted or repeats a slot".to_string(),
            };
            (
                Code::WithheldMismatch,
                format!("redacted_slots does not equal the withheld slots: {why}"),
            )
        });
        self.outcome(
            "4",
            "withheld slots",
            failure,
            format!("{} withheld slot(s), all listed", actual.len()),
        );
    }

    fn erasures(&mut self, j: &Journal) {
        let audit = j.audit();
        let mut failed = false;
        if let Some(&(c, s)) = audit.unaccounted_erasures.first() {
            failed = true;
            self.outcome(
                "5",
                "erasures accounted for",
                Some((
                    Code::UnaccountedErasure,
                    format!(
                        "{} erased slot(s) no later erasure note lists, first {c}:{s}",
                        audit.unaccounted_erasures.len()
                    ),
                )),
                "",
            );
        }
        if let Some(&(c, s)) = audit.erasure_incomplete.first() {
            failed = true;
            self.outcome(
                "5",
                "erasures accounted for",
                Some((
                    Code::ErasureIncomplete,
                    format!("slot {c}:{s} is listed as erased but still holds content"),
                )),
                "",
            );
        }
        if let Some(&c) = audit.invalid_erasure_notes.first() {
            failed = true;
            self.outcome(
                "5",
                "erasures accounted for",
                Some((
                    Code::InvalidErasureNote,
                    format!("the erasure note at cursor {c} lists slots that do not exist"),
                )),
                "",
            );
        }
        if !failed {
            let erased = j
                .entries()
                .iter()
                .flat_map(|e| &e.slots)
                .filter(|m| m.state == crate::journal::SlotState::Erased)
                .count();
            self.check(
                "5",
                "erasures accounted for",
                CheckStatus::Pass,
                format!("{erased} erased slot(s), each listed by a later erasure note"),
            );
        }
    }

    fn records(&mut self, j: &Journal) {
        let given = &self.bundle.records;
        let expected: Vec<Record> = j.entries().iter().filter_map(Record::of_entry).collect();
        let failure = if given.len() != expected.len() {
            Some(format!(
                "records has {} entries; the journal has {}",
                given.len(),
                expected.len()
            ))
        } else {
            given
                .iter()
                .zip(&expected)
                .position(|(g, e)| g.to_json().canonical_string() != e.to_json().canonical_string())
                .map(|i| format!("record {i} differs from the journal's entry at that cursor"))
        };
        self.outcome(
            "6",
            "records equal the journal",
            failure.map(|m| (Code::RecordsMismatch, m)),
            format!(
                "{} records, each equal to the decoded entry",
                expected.len()
            ),
        );
    }

    fn run_start(&mut self, j: &Journal) {
        let failure = match j.run_start_id() {
            Some(id) if id == self.bundle.run_id => None,
            Some(id) => Some(format!(
                "run.start names run {id:?}; the bundle says {:?}",
                self.bundle.run_id
            )),
            None => Some("the journal does not start with a run.start note".to_string()),
        };
        self.outcome(
            "7",
            "run id",
            failure.map(|m| (Code::RunIdMismatch, m)),
            "run.start names the bundle's run",
        );
    }

    // -- step 8 to 10: anchors ----------------------------------------------

    /// Check every anchor, and return the parsed latest checkpoint.
    fn anchors(&mut self, j: &Journal) -> Option<ParsedCheckpoint> {
        let bundle = self.bundle;
        let anchors = &bundle.anchors;
        if anchors.is_empty() {
            self.check(
                "8",
                "anchors",
                CheckStatus::Info,
                "no anchors: nothing ties this journal to a time",
            );
            self.finding(Code::NoAnchors, "the bundle has no anchors");
            return None;
        }
        let latest = match self
            .bundle
            .latest_checkpoint
            .as_deref()
            .map(parse_checkpoint)
        {
            Some(Ok(p)) => {
                self.log_signature(&p.note, "the latest checkpoint");
                Some(p)
            }
            Some(Err(e)) => {
                self.finding(
                    Code::AnchorConsistency,
                    format!("latest_checkpoint is not a checkpoint: {e}"),
                );
                None
            }
            None => {
                self.finding(
                    Code::AnchorConsistency,
                    "the bundle has anchors but no latest_checkpoint",
                );
                None
            }
        };
        let heads = prefix_heads(j);
        let expected_id = leaf_id(&self.bundle.run_id, self.bundle.anchor_id.as_ref());
        let mut previous: Option<(&Anchor, Option<Leaf>)> = None;
        for anchor in anchors {
            let failures_before = self.failure_count();
            let leaf = self.anchor_leaf(anchor, &expected_id, &heads, previous.as_ref());
            self.anchor_tree(anchor, latest.as_ref());
            let mut witnesses = Vec::new();
            let checkpoint = parse_checkpoint(&anchor.checkpoint).ok();
            if let Some(cp) = &checkpoint {
                witnesses.push(self.server_witness(cp));
                for w in &anchor.witnesses {
                    witnesses.push(self.witness(anchor, cp, w));
                }
            }
            let sound = self.failure_count() == failures_before;
            let report = self.anchor_report(anchor, leaf.as_ref(), sound, witnesses);
            self.report.anchors.push(report);
            previous = Some((anchor, leaf));
        }
        let independent = self.report.anchors.iter().filter(|a| a.independent).count();
        let all_sound = self.report.anchors.iter().all(|a| a.sound);
        self.check(
            "8",
            "anchors",
            if all_sound {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            },
            format!(
                "{} anchor(s), {}; {independent} independently witnessed",
                anchors.len(),
                if all_sound {
                    "each leaf, inclusion proof, checkpoint, digest and consistency proof verifies"
                } else {
                    "some fail their checks"
                }
            ),
        );
        latest
    }

    fn failure_count(&self) -> usize {
        self.report.failures().count()
    }

    /// Leaf recomputation, the head it anchors, and leaf chain continuity.
    fn anchor_leaf(
        &mut self,
        anchor: &Anchor,
        expected_id: &[u8],
        heads: &[Digest],
        previous: Option<&(&Anchor, Option<Leaf>)>,
    ) -> Option<Leaf> {
        let seq = anchor.seq;
        let leaf = match Leaf::decode(&anchor.leaf) {
            Ok(l) => l,
            Err(why) => {
                self.finding(Code::AnchorLeaf, format!("anchor {seq}: {why}"));
                return None;
            }
        };
        if leaf.kind != LEAF_RUN {
            self.finding(
                Code::AnchorLeaf,
                format!("anchor {seq}: the leaf is not a run leaf"),
            );
        }
        if leaf.id != expected_id {
            self.finding(
                Code::RunIdMismatch,
                format!("anchor {seq}: the leaf names another run"),
            );
        }
        match heads.get(leaf.entries as usize) {
            Some(h) if *h == leaf.head => {}
            Some(_) => self.finding(
                Code::AnchorHeadMismatch,
                format!(
                    "anchor {seq}: the journal's head after {} entries is not the leaf's head",
                    leaf.entries
                ),
            ),
            None => self.finding(
                Code::AnchorHeadMismatch,
                format!(
                    "anchor {seq}: the leaf anchors {} entries; the journal has {}",
                    leaf.entries,
                    heads.len() - 1
                ),
            ),
        }
        self.leaf_chain(anchor, &leaf, previous);
        Some(leaf)
    }

    /// The anchors must be the run's leaf chain, first leaf first, each
    /// pointing at the one before it.
    fn leaf_chain(
        &mut self,
        anchor: &Anchor,
        leaf: &Leaf,
        previous: Option<&(&Anchor, Option<Leaf>)>,
    ) {
        let seq = anchor.seq;
        match previous {
            None => {
                if leaf.prev_leaf_index.is_some() {
                    self.finding(
                        Code::AnchorChain,
                        format!(
                            "anchor {seq}: the first anchor is not the run's first leaf (it points to leaf {})",
                            leaf.prev_leaf_index.unwrap_or_default()
                        ),
                    );
                }
            }
            Some((prev, prev_leaf)) => {
                if leaf.prev_leaf_index != Some(prev.leaf_index) {
                    self.finding(
                        Code::AnchorChain,
                        format!(
                            "anchor {seq}: its leaf does not point to the previous anchor's leaf {} (an anchor is missing between them)",
                            prev.leaf_index
                        ),
                    );
                }
                if anchor.seq <= prev.seq || anchor.leaf_index <= prev.leaf_index {
                    self.finding(
                        Code::AnchorChain,
                        format!("anchor {seq}: anchors are not in log order"),
                    );
                }
                if let Some(p) = prev_leaf {
                    if leaf.entries < p.entries {
                        self.finding(
                            Code::AnchorChain,
                            format!(
                                "anchor {seq}: anchors {} entries after an anchor of {}",
                                leaf.entries, p.entries
                            ),
                        );
                    }
                }
            }
        }
    }

    /// Inclusion, the checkpoint's statement, the anchor digest and
    /// consistency with the latest checkpoint.
    fn anchor_tree(&mut self, anchor: &Anchor, latest: Option<&ParsedCheckpoint>) {
        let seq = anchor.seq;
        let leaf_hash = merkle::leaf_hash(&anchor.leaf);
        if !merkle::verify_inclusion(
            &leaf_hash,
            anchor.leaf_index,
            anchor.tree_size,
            &anchor.inclusion_proof,
            &anchor.root,
        ) {
            self.finding(
                Code::AnchorInclusion,
                format!(
                    "anchor {seq}: the inclusion proof does not lead from leaf {} to the root",
                    anchor.leaf_index
                ),
            );
        }
        match parse_checkpoint(&anchor.checkpoint) {
            Err(e) => self.finding(
                Code::AnchorCheckpoint,
                format!("anchor {seq}: the checkpoint is malformed: {e}"),
            ),
            Ok(cp) => {
                let c = &cp.checkpoint;
                if c.tree_size != anchor.tree_size || c.root != anchor.root {
                    self.finding(
                        Code::AnchorCheckpoint,
                        format!("anchor {seq}: the checkpoint does not state the anchor's tree size and root"),
                    );
                }
                if let Some(l) = latest {
                    if l.checkpoint.origin != c.origin {
                        self.finding(
                            Code::AnchorCheckpoint,
                            format!("anchor {seq}: the checkpoint is from another log than latest_checkpoint"),
                        );
                    }
                }
                if sha256(cp.note.body.as_bytes()) != anchor.anchor_digest {
                    self.finding(
                        Code::AnchorDigest,
                        format!(
                            "anchor {seq}: anchor_digest is not SHA-256 of the checkpoint body"
                        ),
                    );
                }
                self.log_signature(&cp.note, &format!("anchor {seq}'s checkpoint"));
            }
        }
        if let Some(l) = latest {
            let ok = merkle::verify_consistency(
                anchor.tree_size,
                l.checkpoint.tree_size,
                &anchor.root,
                &l.checkpoint.root,
                &anchor.consistency_to_latest,
            );
            if !ok {
                self.finding(
                    Code::AnchorConsistency,
                    format!(
                        "anchor {seq}: the consistency proof does not lead to latest_checkpoint"
                    ),
                );
            }
        }
    }

    /// A checkpoint's server signature against the pinned log keys, if any.
    fn log_signature(&mut self, note: &Note, what: &str) {
        if self.policy.log_keys.is_empty() {
            return;
        }
        if let Err(e) = note::verify_note(note, &self.policy.log_keys) {
            self.finding(
                Code::LogSignature,
                format!("{what} is not signed by a pinned log key: {e}"),
            );
        }
    }

    /// The checkpoint's own signature, always operator-controlled.
    fn server_witness(&self, cp: &ParsedCheckpoint) -> WitnessReport {
        let verified = !self.policy.log_keys.is_empty()
            && note::verify_note(&cp.note, &self.policy.log_keys).is_ok();
        WitnessReport {
            kind: "server-ed25519",
            label: cp.checkpoint.origin.clone(),
            claimed_operator: None,
            operator: None,
            class: WitnessClass::OperatorControlled,
            time: None,
            code: None,
            detail: if verified {
                "the log's checkpoint signature verifies with the pinned log key".into()
            } else {
                "the log's checkpoint signature (not checked: no log key pinned)".into()
            },
        }
    }

    fn witness(&mut self, anchor: &Anchor, cp: &ParsedCheckpoint, w: &Witness) -> WitnessReport {
        match w {
            Witness::Rfc3161 {
                tsa,
                operator,
                token,
                certs_pem,
            } => self.tsa_witness(anchor, tsa, operator, token, certs_pem),
            Witness::Cosignature { name, line } => self.cosignature(anchor, cp, name, line),
        }
    }

    fn tsa_witness(
        &mut self,
        anchor: &Anchor,
        url: &str,
        claimed: &str,
        token: &[u8],
        certs_pem: &str,
    ) -> WitnessReport {
        let seq = anchor.seq;
        let mut report = WitnessReport {
            kind: "rfc3161",
            label: url.to_string(),
            claimed_operator: Some(claimed.to_string()),
            operator: None,
            class: WitnessClass::SelfAsserted,
            time: None,
            code: None,
            detail: String::new(),
        };
        let info = match tsp::parse_token(token) {
            Ok(i) => i,
            Err(e) => {
                let msg = format!("anchor {seq}: a time-stamp token is malformed: {e}");
                self.finding(Code::WitnessMalformed, msg.clone());
                report.code = Some(Code::WitnessMalformed);
                report.detail = msg;
                return report;
            }
        };
        report.time = Some(tsa_time(&info));
        if !info.imprint_matches(&anchor.anchor_digest) {
            let msg = format!(
                "anchor {seq}: a time-stamp token stamps something other than the anchor digest"
            );
            self.finding(Code::TsaImprintMismatch, msg.clone());
            report.code = Some(Code::TsaImprintMismatch);
            report.detail = msg;
            return report;
        }
        if let Err(why) = check_certs_pem(certs_pem) {
            let msg = format!("anchor {seq}: certs_pem is not PEM certificates: {why}");
            self.finding(Code::WitnessMalformed, msg.clone());
            report.code = Some(Code::WitnessMalformed);
            report.detail = msg;
            return report;
        }
        let (code, detail) =
            self.tsa_trust(token, &anchor.anchor_digest, certs_pem, &info, &mut report);
        if let Some(code) = code {
            report.code = Some(code);
            self.finding(code, format!("anchor {seq}: TSA {url:?}: {detail}"));
        } else if let Some(op) = &report.operator {
            if self.policy.operator(claimed) != *op {
                self.finding(
                    Code::OperatorMismatch,
                    format!(
                        "anchor {seq}: the bundle names the TSA's operator {claimed:?}; the pinned root that verifies it is {op:?}"
                    ),
                );
            }
        }
        report.detail = detail;
        report
    }

    /// Try each pinned root in turn. Returns the untrusted code (if any)
    /// and a description; marks `report` trusted on success.
    fn tsa_trust(
        &mut self,
        token: &[u8],
        digest: &Digest,
        certs_pem: &str,
        info: &tsp::TstInfo,
        report: &mut WitnessReport,
    ) -> (Option<Code>, String) {
        if self.policy.tsa_roots.is_empty() {
            return (
                Some(Code::TsaUntrusted),
                "no TSA roots are pinned (pass --tsa-roots)".into(),
            );
        }
        let mut last = String::new();
        for root in &self.policy.tsa_roots {
            self.tsa_index += 1;
            let check = TsaCheck {
                index: self.tsa_index,
                token,
                digest,
                certs_pem,
                root: &root.path,
                at_time: info.gen_time_unix.saturating_add(1),
            };
            match self.tsa.verify(&check) {
                TsaResult::Verified => {
                    let op = self.policy.operator(&root.operator);
                    report.class = WitnessClass::Trusted;
                    report.operator = Some(op.clone());
                    return (None, format!("verified against the pinned root for {op}"));
                }
                TsaResult::Rejected(why) => last = why,
                TsaResult::Unavailable(why) => {
                    return (Some(Code::TsaUnchecked), format!("not checked: {why}"));
                }
            }
        }
        (
            Some(Code::TsaUntrusted),
            format!("does not verify against any pinned root ({last})"),
        )
    }

    fn cosignature(
        &mut self,
        anchor: &Anchor,
        cp: &ParsedCheckpoint,
        name: &str,
        line: &str,
    ) -> WitnessReport {
        let seq = anchor.seq;
        let mut report = WitnessReport {
            kind: "cosignature",
            label: name.to_string(),
            claimed_operator: None,
            operator: None,
            class: WitnessClass::SelfAsserted,
            time: None,
            code: None,
            detail: String::new(),
        };
        let sig = match NoteSignature::parse_line(line) {
            Ok(s) if s.name == name => s,
            Ok(_) => {
                return self.malformed(
                    report,
                    format!(
                        "anchor {seq}: a cosignature line names another witness than its entry"
                    ),
                );
            }
            Err(e) => {
                return self.malformed(
                    report,
                    format!("anchor {seq}: a cosignature line is malformed: {e}"),
                );
            }
        };
        let matching: Vec<&WitnessKey> = self
            .policy
            .witness_keys
            .iter()
            .filter(|k| k.key.matches(&sig))
            .collect();
        if matching.is_empty() {
            let msg =
                format!("no pinned witness key for {name:?} with this key id (pass --witness-key)");
            self.finding(Code::CosignatureUntrusted, format!("anchor {seq}: {msg}"));
            report.code = Some(Code::CosignatureUntrusted);
            report.detail = msg;
            return report;
        }
        let Some(key) = matching
            .into_iter()
            .find(|k| k.key.verify(&cp.note.body, &sig))
        else {
            let msg = format!(
                "anchor {seq}: the cosignature from {name:?} does not verify with its pinned key"
            );
            self.finding(Code::CosignatureInvalid, msg.clone());
            report.code = Some(Code::CosignatureInvalid);
            report.detail = msg;
            return report;
        };
        let timestamp = sig.cosignature_timestamp();
        report.time = timestamp.map(|t| SignedTime {
            unix: t.min(i64::MAX as u64) as i64,
            nanos: 0,
        });
        let in_window = timestamp.is_some_and(|t| {
            key.not_before.is_none_or(|nb| t >= nb) && key.not_after.is_none_or(|na| t <= na)
        }) || (key.not_before.is_none() && key.not_after.is_none());
        if !in_window {
            let msg = format!(
                "the cosignature from {name:?} is outside its pinned key's validity window"
            );
            self.finding(Code::WitnessKeyExpired, format!("anchor {seq}: {msg}"));
            report.code = Some(Code::WitnessKeyExpired);
            report.detail = msg;
            return report;
        }
        let op = self.policy.operator(&key.operator);
        report.class = WitnessClass::Trusted;
        report.operator = Some(op.clone());
        report.detail = format!("verified with the pinned key for {op}");
        report
    }

    fn malformed(&mut self, mut report: WitnessReport, msg: String) -> WitnessReport {
        self.finding(Code::WitnessMalformed, msg.clone());
        report.code = Some(Code::WitnessMalformed);
        report.detail = msg;
        report
    }

    fn anchor_report(
        &self,
        anchor: &Anchor,
        leaf: Option<&Leaf>,
        sound: bool,
        witnesses: Vec<WitnessReport>,
    ) -> AnchorReport {
        let trusted: BTreeSet<String> = witnesses
            .iter()
            .filter(|w| w.class == WitnessClass::Trusted)
            .filter_map(|w| w.operator.clone())
            .collect();
        let earliest = witnesses
            .iter()
            .filter(|w| w.class == WitnessClass::Trusted)
            .filter_map(|w| w.time)
            .min();
        let independent = sound && trusted.len() >= self.policy.min_operators.max(1);
        AnchorReport {
            seq: anchor.seq,
            entries: leaf.map_or(0, |l| l.entries),
            tree_size: anchor.tree_size,
            leaf_index: anchor.leaf_index,
            sound,
            witnesses,
            trusted_operators: trusted.into_iter().collect(),
            independent,
            earliest,
        }
    }

    // -- step 11: full-log audits -------------------------------------------

    fn full_log(&mut self, _j: &Journal, latest: Option<&ParsedCheckpoint>) {
        let audit = self.audit;
        let Some(log) = &audit.log else {
            return;
        };
        const NAME: &str = "full log (--log)";
        let Some(latest) = latest else {
            self.outcome(
                "11",
                NAME,
                Some((
                    Code::LogMismatch,
                    "the bundle has no latest checkpoint to check the log against".into(),
                )),
                "",
            );
            return;
        };
        let size = latest.checkpoint.tree_size;
        if (log.leaves.len() as u64) < size {
            self.outcome(
                "11",
                NAME,
                Some((
                    Code::LogMismatch,
                    format!(
                        "the log has {} leaves; the latest checkpoint covers {size}",
                        log.leaves.len()
                    ),
                )),
                "",
            );
            return;
        }
        let covered = &log.leaves[..size as usize];
        let hashes: Vec<Digest> = covered.iter().map(|l| merkle::leaf_hash(l)).collect();
        if merkle::root(&hashes) != latest.checkpoint.root {
            self.outcome(
                "11",
                NAME,
                Some((
                    Code::LogMismatch,
                    "the log's leaves do not hash to the latest checkpoint's root".into(),
                )),
                "",
            );
            return;
        }
        self.report.log_leaves_checked = Some(size);
        let bundle = self.bundle;
        let expected_id = leaf_id(&bundle.run_id, bundle.anchor_id.as_ref());
        let in_bundle: BTreeMap<u64, &Vec<u8>> = bundle
            .anchors
            .iter()
            .map(|a| (a.leaf_index, &a.leaf))
            .collect();
        let before = self.failure_count();
        for (index, data) in log.leaves.iter().enumerate() {
            let index = index as u64;
            if let Some(&bundled) = in_bundle.get(&index) {
                if bundled != data && index < size {
                    self.finding(
                        Code::LogMismatch,
                        format!("the log's leaf {index} differs from the bundle's anchor"),
                    );
                }
                continue;
            }
            let Ok(leaf) = Leaf::decode(data) else {
                continue;
            };
            if leaf.kind != LEAF_RUN || leaf.id != expected_id {
                continue;
            }
            if index < size {
                self.finding(
                    Code::AnchorOmitted,
                    format!(
                        "the log's leaf {index} anchors this run at {} entries, and the bundle leaves it out",
                        leaf.entries
                    ),
                );
            } else {
                self.finding(
                    Code::LogNewer,
                    format!(
                        "the log's leaf {index}, past the bundle's latest checkpoint, anchors this run at {} entries (the bundle may predate it)",
                        leaf.entries
                    ),
                );
            }
        }
        for a in &bundle.anchors {
            if a.leaf_index >= size {
                self.finding(
                    Code::LogMismatch,
                    format!("anchor {} is past the latest checkpoint", a.seq),
                );
            }
        }
        let ok = self.failure_count() == before;
        self.check(
            "11",
            NAME,
            if ok { CheckStatus::Pass } else { CheckStatus::Fail },
            if ok {
                format!("all {size} leaves hash to the latest root; every leaf of this run is in the bundle")
            } else {
                "the log shows anchors the bundle does not account for".to_string()
            },
        );
    }

    fn witness_logs(&mut self, latest: Option<&ParsedCheckpoint>) {
        let audit = self.audit;
        for wl in &audit.witness_logs {
            self.witness_log(wl, latest);
        }
    }

    fn witness_log(&mut self, wl: &WitnessLog, latest: Option<&ParsedCheckpoint>) {
        const NAME: &str = "witness log (--witness-log)";
        if let Some(l) = latest {
            if l.checkpoint.origin != wl.origin {
                self.finding(
                    Code::WitnessLogOrigin,
                    format!(
                        "the witness log of {:?} is for another log origin",
                        wl.witness
                    ),
                );
                self.check(
                    "11",
                    NAME,
                    CheckStatus::Skipped,
                    "the witness log is for another log",
                );
                return;
            }
        }
        let before = self.failure_count();
        let mut seen: BTreeMap<u64, Digest> = BTreeMap::new();
        for note in &wl.checkpoints {
            let Ok(c) = Checkpoint::parse(&note.body) else {
                continue;
            };
            if c.origin != wl.origin {
                continue;
            }
            if let Some(root) = seen.insert(c.tree_size, c.root) {
                if root != c.root {
                    self.finding(
                        Code::WitnessLogFork,
                        format!(
                            "the witness cosigned two roots for tree size {}",
                            c.tree_size
                        ),
                    );
                }
            }
        }
        let mut ours: Vec<(String, Checkpoint, bool)> = Vec::new();
        let bundle = self.bundle;
        for a in &bundle.anchors {
            if let Ok(cp) = parse_checkpoint(&a.checkpoint) {
                let cosigned = a
                    .witnesses
                    .iter()
                    .any(|w| matches!(w, Witness::Cosignature { name, .. } if *name == wl.witness));
                ours.push((format!("anchor {}", a.seq), cp.checkpoint, cosigned));
            }
        }
        if let Some(l) = latest {
            ours.push(("the latest checkpoint".into(), l.checkpoint.clone(), false));
        }
        for (what, c, cosigned) in ours {
            match seen.get(&c.tree_size) {
                Some(root) if *root != c.root => self.finding(
                    Code::WitnessLogFork,
                    format!(
                        "{what}: the witness cosigned another root for tree size {} (the log showed two histories)",
                        c.tree_size
                    ),
                ),
                None if cosigned => self.finding(
                    Code::WitnessLogMismatch,
                    format!(
                        "{what} carries a cosignature from {:?}, but the witness's own log does not list it",
                        wl.witness
                    ),
                ),
                _ => {}
            }
        }
        let ok = self.failure_count() == before;
        self.check(
            "11",
            NAME,
            if ok {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            },
            if ok {
                format!(
                    "{} cosigned checkpoint(s) from {:?}, consistent with the bundle",
                    wl.checkpoints.len(),
                    wl.witness
                )
            } else {
                "the witness's history disagrees with the bundle".to_string()
            },
        );
    }

    // -- verdict ------------------------------------------------------------

    fn verdict(&mut self, j: &Journal) {
        if self.failure_count() > 0 {
            self.report.verdict = Verdict::Failed;
            self.check(
                "10",
                "independence",
                CheckStatus::Skipped,
                "integrity checks failed",
            );
            return;
        }
        let anchored = self
            .report
            .anchors
            .iter()
            .filter(|a| a.independent)
            .map(|a| a.entries)
            .max();
        let min = self.policy.min_operators.max(1);
        self.report.verdict = match anchored {
            None => Verdict::Unanchored,
            Some(n) if n >= j.len() => Verdict::Verified,
            Some(n) => Verdict::Partial {
                unanchored: j.len() - n,
            },
        };
        self.report.anchored_entries = anchored.unwrap_or(0).min(j.len());
        let detail = match self.report.verdict {
            Verdict::Verified => format!(
                "all {} entries are anchored with at least {min} distinct trusted operator(s)",
                j.len()
            ),
            Verdict::Partial { unanchored } => format!(
                "the first {} entries are anchored with at least {min} distinct trusted operator(s); the last {unanchored} are not",
                self.report.anchored_entries
            ),
            _ => format!("no anchor has {min} distinct trusted operator(s)"),
        };
        self.check("10", "independence", CheckStatus::Info, detail);
    }
}

/// `heads[n]` is the chain head after `n` entries (`heads[0]` the genesis).
fn prefix_heads(j: &Journal) -> Vec<Digest> {
    let mut heads = Vec::with_capacity(j.entries().len() + 1);
    heads.push(j.genesis());
    heads.extend(j.entries().iter().map(|e| e.hash));
    heads
}

/// `genTime` plus the stated accuracy: the latest instant the token can
/// mean (design 5.3 step 9).
fn tsa_time(info: &tsp::TstInfo) -> SignedTime {
    let mut nanos = i128::from(info.gen_time_nanos);
    if let Some(a) = info.accuracy {
        nanos += i128::from(a.seconds.unwrap_or(0)) * 1_000_000_000;
        nanos += i128::from(a.millis.unwrap_or(0)) * 1_000_000;
        nanos += i128::from(a.micros.unwrap_or(0)) * 1_000;
    }
    let secs = i128::from(info.gen_time_unix) + nanos.div_euclid(1_000_000_000);
    SignedTime {
        unix: secs.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64,
        nanos: nanos.rem_euclid(1_000_000_000) as u32,
    }
}

/// `certs_pem` must be zero or more `CERTIFICATE` blocks whose bodies are
/// canonical base64 in lines of at most 64 characters. It is written to a
/// file and handed to OpenSSL, so anything else (keys, other block types,
/// text OpenSSL might interpret) is refused.
fn check_certs_pem(pem: &str) -> Result<(), &'static str> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut body: Option<String> = None;
    for line in pem.lines() {
        match (&mut body, line) {
            (None, "") => {}
            (None, BEGIN) => body = Some(String::new()),
            (None, _) => return Err("text outside a CERTIFICATE block"),
            (Some(b), END) => {
                if b.is_empty() || crate::encoding::base64_decode(b).is_err() {
                    return Err("a certificate is not canonical base64");
                }
                body = None;
            }
            (Some(b), l) => {
                if l.len() > 64 || l.is_empty() {
                    return Err("a certificate line is not 1 to 64 characters");
                }
                b.push_str(l);
            }
        }
    }
    if body.is_some() {
        return Err("a CERTIFICATE block is not closed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operators_normalize_and_alias() {
        assert_eq!(normalize_operator("  QuoVadis   EU "), "quovadis-eu");
        assert_eq!(normalize_operator("Digi_Cert"), "digi-cert");
        let p = TrustPolicy::default();
        assert_eq!(p.operator("Entrust"), "sectigo");
        assert_eq!(p.operator("QuoVadis EU"), "digicert");
        assert_eq!(p.operator("FreeTSA"), "freetsa");
    }

    #[test]
    fn certs_pem_must_be_certificate_blocks() {
        let ok = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n";
        assert!(check_certs_pem(ok).is_ok());
        assert!(check_certs_pem("").is_ok());
        assert!(check_certs_pem(&format!("{ok}\n{ok}")).is_ok());
        for bad in [
            "hello\n",
            "-----BEGIN CERTIFICATE-----\nQUJD\n",
            "-----BEGIN CERTIFICATE-----\nQUI\n-----END CERTIFICATE-----\n",
            "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n",
            "-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n",
        ] {
            assert!(check_certs_pem(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn tsa_time_adds_accuracy() {
        let tokens: &[(&str, &[u8])] = &[
            (
                "sigstore",
                include_bytes!("../../tests/fixtures/tsp/sigstore.tsr"),
            ),
            (
                "microsoft",
                include_bytes!("../../tests/fixtures/tsp/microsoft.tsr"),
            ),
        ];
        for (name, tsr) in tokens {
            let resp = tsp::parse_response(tsr).unwrap();
            let info = tsp::parse_token(resp.token.as_ref().unwrap()).unwrap();
            let t = tsa_time(&info);
            let base = SignedTime {
                unix: info.gen_time_unix,
                nanos: info.gen_time_nanos,
            };
            assert!(t > base, "{name}: accuracy moves the time later");
        }
    }

    #[test]
    fn verdict_exit_codes() {
        assert_eq!(Verdict::Verified.exit_code(), 0);
        assert_eq!(Verdict::Failed.exit_code(), 1);
        assert_eq!(Verdict::Partial { unanchored: 3 }.exit_code(), 2);
        assert_eq!(Verdict::Unanchored.exit_code(), 3);
        let names: BTreeSet<&str> = Code::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), Code::ALL.len(), "codes are distinct");
    }
}
