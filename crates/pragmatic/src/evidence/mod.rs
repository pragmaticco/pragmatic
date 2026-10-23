//! Evidence bundles (design section 5): one run's journal, packaged so a
//! party who trusts neither the agent's operator nor Pragmatic Research
//! can check it offline against trust roots of their own choosing.
//!
//! A bundle is one strict JSON file. It carries the journal bytes (with
//! some slots possibly withheld for privacy), the same journal decoded as
//! readable `records`, and the run's *anchors*: the leaves of the server's
//! append-only Merkle log that commit to the journal's head at different
//! lengths, each with its inclusion proof, the signed checkpoint it is in,
//! and the witnesses (RFC 3161 time-stamps, C2SP cosignatures) that vouch
//! for that checkpoint's existence at a time.
//!
//! - [`Bundle`] is the format, read with [`Bundle::from_json`] (strict
//!   JSON, every object's key set fixed) and written with
//!   [`Bundle::to_json`] (canonical: keys sorted by UTF-8 bytes, no
//!   insignificant white space).
//! - [`Bundle::local`] builds an unanchored bundle from a local journal,
//!   and [`Bundle::withhold`] withholds more slots.
//! - [`verify`] runs every check of design 5.3 against a [`TrustPolicy`]
//!   and returns an [`EvidenceReport`] with a verdict and its exit code.
//!
//! Nothing in a bundle is ever a trust anchor. Keys, roots and operator
//! names come from the verifier's own inputs; the bundle only supplies what
//! is checked against them. The core never runs processes: RFC 3161
//! signature checks go through the [`TsaVerifier`] trait, which the CLI
//! implements with OpenSSL.
//!
//! The normative description of the format and of the verification
//! procedure is `docs/evidence-format.md`; `tools/verify_evidence.py` is
//! an independent implementation of the same checks.

mod build;
mod leaf;
mod records;
mod schema;
pub mod time;
mod verify;

pub use build::Redact;
pub use leaf::{
    leaf_id, AnchorLog, Leaf, WitnessLog, LEAF_ACCESS_LOG, LEAF_RUN, LEAF_TAG, MAX_LEAF_ID,
    NO_PREVIOUS,
};
pub use records::{state_name, Record, RecordSlot};
pub use verify::{
    normalize_operator, verify, verify_bytes, verify_with, AnchorReport, Audit, Check, CheckStatus,
    Code, EvidenceReport, Finding, NoTsaVerifier, Severity, SignatureStatus, SignedTime,
    TrustPolicy, TsaCheck, TsaResult, TsaRoot, TsaVerifier, Verdict, WitnessClass, WitnessKey,
    WitnessReport, DEFAULT_OPERATOR_ALIASES,
};

use std::fmt;

use crate::encoding::{base64_decode, base64_encode, hex_decode_exact, hex_encode};
use crate::json::Json;
use crate::sha256::{sha256, Digest};

use schema::Obj;

/// The `format` of every bundle this module reads and writes.
pub const FORMAT: &str = "pragmatic-evidence/1";

/// Above this size a bundle is written as a directory, with the journal in
/// a file of its own referenced by SHA-256 (design 5.1).
pub const DIRECTORY_THRESHOLD: u64 = 100 << 20;

/// The file name of the bundle JSON inside a directory bundle.
pub const DIRECTORY_BUNDLE_FILE: &str = "evidence.json";

/// The file name of the journal inside a directory bundle.
pub const DIRECTORY_JOURNAL_FILE: &str = "journal.pragmatic";

/// An evidence bundle (design 5.1).
#[derive(Clone, Debug, PartialEq)]
pub struct Bundle {
    /// When the bundle was made, RFC 3339 UTC. Informational: no check
    /// relies on it, and reported times come from signed structures.
    pub generated_at: String,
    /// What made it, such as `pragmatic-server 0.6.0`.
    pub generator: String,
    /// Who asked for it: a token id, or `local:<os-user>@<host>`.
    pub requested_by: String,
    /// The run the journal belongs to.
    pub run_id: String,
    /// The per-run key `k_run` when the anchor log names runs by
    /// `HMAC-SHA-256(k_run, run_id)`; `None` when leaves carry the run id.
    pub anchor_id: Option<[u8; 32]>,
    /// The generator's claim that its anchors are independently witnessed.
    /// Informational: the verifier decides independence from its own trust
    /// inputs.
    pub independent: bool,
    pub journal: JournalData,
    pub redaction: Redaction,
    /// The withheld slots, sorted and without repeats.
    pub redacted_slots: Vec<(u64, u8)>,
    pub records: Vec<Record>,
    /// The run's full leaf chain, first leaf first.
    pub anchors: Vec<Anchor>,
    /// The log's latest checkpoint (a signed note) that every anchor's
    /// consistency proof leads to. `None` only for an unanchored bundle.
    pub latest_checkpoint: Option<String>,
    pub verification_spec: Option<VerificationSpec>,
    /// The generator's signature, `None` for an unsigned (local) bundle.
    pub signature: Option<BundleSignature>,
}

/// The journal inside a bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalData {
    pub encoding: JournalEncoding,
    /// The journal file bytes. Empty for a [`JournalEncoding::File`] bundle
    /// until [`Bundle::attach_journal`] supplies them.
    pub bytes: Vec<u8>,
    /// The number of entries, as the generator states it.
    pub entries: u64,
    /// The chain head, as the generator states it.
    pub head: Digest,
}

/// How the journal is carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalEncoding {
    /// Inline, base64 (`"encoding": "base64", "data": ...`).
    Base64,
    /// In a separate file next to the bundle JSON (`"encoding": "file",
    /// "path": ..., "sha256": ...`): the directory form for bundles over
    /// [`DIRECTORY_THRESHOLD`]. `path` is a plain file name.
    File { path: String, sha256: Digest },
}

/// How content was withheld (design 5.1 `redaction`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redaction {
    /// `none`, `detectors`, `binary` or `all`.
    pub mode: String,
    /// The detectors that were applied, by name.
    pub detectors: Vec<String>,
    /// SHA-256 of the canonical JSON array of the configured patterns
    /// (`[]` when there are none), so two bundles can be compared without
    /// disclosing the patterns.
    pub patterns_sha256: Digest,
}

/// The redaction modes.
pub const REDACTION_MODES: [&str; 4] = ["none", "detectors", "binary", "all"];

/// One anchor: a leaf of the anchor log, where it is, and who vouches for
/// the checkpoint it is in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// The anchoring batch number.
    pub seq: u64,
    /// The size of the checkpoint's tree.
    pub tree_size: u64,
    /// The leaf's index in the log.
    pub leaf_index: u64,
    /// The leaf data ([`Leaf::encode`]).
    pub leaf: Vec<u8>,
    /// RFC 9162 inclusion proof of the leaf in the checkpoint's tree.
    pub inclusion_proof: Vec<Digest>,
    /// The checkpoint's root.
    pub root: Digest,
    /// The checkpoint as a signed note (body and the server's signature).
    pub checkpoint: String,
    /// SHA-256 of the checkpoint body: what the witnesses time-stamp.
    pub anchor_digest: Digest,
    /// RFC 9162 consistency proof from this tree to `latest_checkpoint`.
    pub consistency_to_latest: Vec<Digest>,
    pub witnesses: Vec<Witness>,
}

/// A witness of one checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Witness {
    /// An RFC 3161 time-stamp token over `anchor_digest`.
    Rfc3161 {
        /// The TSA's URL (informational).
        tsa: String,
        /// The operator the generator names (informational: the verifier
        /// takes the operator from the pinned root that verifies the
        /// token).
        operator: String,
        /// The token, DER (`ContentInfo`).
        token: Vec<u8>,
        /// The TSA's certificate chain as PEM, passed to the verifier as
        /// untrusted intermediates only.
        certs_pem: String,
    },
    /// A C2SP `cosignature/v1` line over the checkpoint body.
    Cosignature {
        /// The cosigner name the line carries.
        name: String,
        /// The signature line: the U+2014 prefix, the name, and
        /// `base64(key id ‖ timestamp ‖ signature)`.
        line: String,
    },
}

/// Where the normative verification procedure lives, and its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationSpec {
    pub url: String,
    pub sha256: Digest,
}

/// The generator's Ed25519 signature over [`Bundle::signature_message`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleSignature {
    /// The signed-note key ID of the key (the same key signs checkpoints).
    pub key_id: [u8; 4],
    pub public_key: [u8; 32],
    pub value: [u8; 64],
}

/// Why a bundle could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleError {
    /// Not strict JSON: invalid UTF-8, a byte-order mark, a duplicate key,
    /// nesting deeper than 64, trailing bytes.
    Json(String),
    /// Strict JSON, but not a bundle: a missing or unknown key, a wrong
    /// type, malformed hex or base64, an unknown format.
    Schema(String),
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleError::Json(m) => write!(f, "bundle is not strict JSON: {m}"),
            BundleError::Schema(m) => write!(f, "bundle does not follow the format: {m}"),
        }
    }
}

impl std::error::Error for BundleError {}

const BUNDLE_KEYS: [&str; 15] = [
    "anchor_id",
    "anchors",
    "format",
    "generated_at",
    "generator",
    "independent",
    "journal",
    "latest_checkpoint",
    "records",
    "redacted_slots",
    "redaction",
    "requested_by",
    "run_id",
    "signature",
    "verification_spec",
];

impl Bundle {
    /// Read a bundle from its file bytes: strict JSON (design 3.7), every
    /// key of every object present and no other.
    ///
    /// A [`JournalEncoding::File`] bundle comes back without its journal
    /// bytes; supply them with [`Bundle::attach_journal`].
    pub fn from_json(bytes: &[u8]) -> Result<Bundle, BundleError> {
        let doc = Json::parse_bytes(bytes).map_err(|e| BundleError::Json(e.to_string()))?;
        Bundle::from_value(&doc).map_err(BundleError::Schema)
    }

    fn from_value(doc: &Json) -> Result<Bundle, String> {
        let o = Obj::new(doc, "bundle", &BUNDLE_KEYS)?;
        if o.str("format")? != FORMAT {
            return Err(format!("bundle.format is not {FORMAT:?}"));
        }
        let generated_at = o.str("generated_at")?.to_string();
        if !time::is_rfc3339_utc(&generated_at) {
            return Err("bundle.generated_at is not an RFC 3339 UTC time".into());
        }
        let anchor_id = match o.opt_str("anchor_id")? {
            None => None,
            Some(h) => {
                Some(hex_decode_exact::<32>(h).map_err(|e| format!("bundle.anchor_id: {e}"))?)
            }
        };
        let redacted_slots = o
            .array("redacted_slots")?
            .iter()
            .enumerate()
            .map(|(i, v)| {
                schema::slot_pair(v)
                    .ok_or_else(|| format!("bundle.redacted_slots[{i}] is not [cursor, slot]"))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let records = o
            .array("records")?
            .iter()
            .enumerate()
            .map(|(i, r)| Record::from_json(r, &format!("bundle.records[{i}]")))
            .collect::<Result<Vec<_>, String>>()?;
        let anchors = o
            .array("anchors")?
            .iter()
            .enumerate()
            .map(|(i, a)| Anchor::from_json(a, &format!("bundle.anchors[{i}]")))
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Bundle {
            generated_at,
            generator: o.str("generator")?.to_string(),
            requested_by: o.str("requested_by")?.to_string(),
            run_id: o.str("run_id")?.to_string(),
            anchor_id,
            independent: o.bool("independent")?,
            journal: JournalData::from_json(o.get("journal"))?,
            redaction: Redaction::from_json(o.get("redaction"))?,
            redacted_slots,
            records,
            anchors,
            latest_checkpoint: o.opt_str("latest_checkpoint")?.map(str::to_string),
            verification_spec: o
                .opt_obj("verification_spec")?
                .map(VerificationSpec::from_json)
                .transpose()?,
            signature: o
                .opt_obj("signature")?
                .map(BundleSignature::from_json)
                .transpose()?,
        })
    }

    /// The bundle as a JSON value (with every key, `null` for absent
    /// values).
    pub fn to_json_value(&self) -> Json {
        let mut members = self.unsigned_members();
        members.push((
            "signature".into(),
            self.signature
                .as_ref()
                .map_or(Json::Null, BundleSignature::to_json),
        ));
        Json::Object(members)
    }

    /// The canonical file form: keys sorted by UTF-8 bytes, no white space.
    pub fn to_json(&self) -> String {
        self.to_json_value().canonical_string()
    }

    /// Every member except `signature`.
    fn unsigned_members(&self) -> Vec<(String, Json)> {
        let opt_str = |s: &Option<String>| s.as_deref().map_or(Json::Null, Json::from);
        vec![
            (
                "anchor_id".into(),
                self.anchor_id.map_or(Json::Null, |k| hex_encode(&k).into()),
            ),
            (
                "anchors".into(),
                Json::Array(self.anchors.iter().map(Anchor::to_json).collect()),
            ),
            ("format".into(), FORMAT.into()),
            ("generated_at".into(), self.generated_at.as_str().into()),
            ("generator".into(), self.generator.as_str().into()),
            ("independent".into(), self.independent.into()),
            ("journal".into(), self.journal.to_json()),
            ("latest_checkpoint".into(), opt_str(&self.latest_checkpoint)),
            (
                "records".into(),
                Json::Array(self.records.iter().map(Record::to_json).collect()),
            ),
            (
                "redacted_slots".into(),
                Json::Array(
                    self.redacted_slots
                        .iter()
                        .map(|&(c, s)| Json::Array(vec![c.into(), s.into()]))
                        .collect(),
                ),
            ),
            ("redaction".into(), self.redaction.to_json()),
            ("requested_by".into(), self.requested_by.as_str().into()),
            ("run_id".into(), self.run_id.as_str().into()),
            (
                "verification_spec".into(),
                self.verification_spec
                    .as_ref()
                    .map_or(Json::Null, VerificationSpec::to_json),
            ),
        ]
    }

    /// What the bundle signature signs: SHA-256 of the canonical bundle
    /// with the `signature` member removed (design 5.1). The message is
    /// always 32 bytes, so it can never be mistaken for a checkpoint or a
    /// cosignature message signed by the same key, which are longer text.
    pub fn signature_message(&self) -> Digest {
        sha256(
            Json::Object(self.unsigned_members())
                .canonical_string()
                .as_bytes(),
        )
    }

    /// Supply the journal of a directory bundle. The bytes must hash to the
    /// bundle's `sha256`.
    pub fn attach_journal(&mut self, bytes: Vec<u8>) -> Result<(), String> {
        match &self.journal.encoding {
            JournalEncoding::Base64 => Err("the journal is inline in this bundle".into()),
            JournalEncoding::File { sha256: want, .. } => {
                if &sha256(&bytes) != want {
                    return Err("the journal file does not match the bundle's sha256".into());
                }
                self.journal.bytes = bytes;
                Ok(())
            }
        }
    }

    /// Switch to the directory form: the journal goes to
    /// [`DIRECTORY_JOURNAL_FILE`] and the bundle references it by SHA-256.
    /// Returns the journal bytes to write next to the bundle JSON. A
    /// signature no longer covers the changed bundle, so it is dropped.
    pub fn into_directory_form(&mut self) -> Vec<u8> {
        self.journal.encoding = JournalEncoding::File {
            path: DIRECTORY_JOURNAL_FILE.to_string(),
            sha256: sha256(&self.journal.bytes),
        };
        self.signature = None;
        self.journal.bytes.clone()
    }
}

impl JournalData {
    fn from_json(value: &Json) -> Result<JournalData, String> {
        let at = "bundle.journal";
        let encoding = value
            .get("encoding")
            .and_then(Json::as_str)
            .ok_or_else(|| format!("{at}.encoding is missing or not a string"))?;
        match encoding {
            "base64" => {
                let o = Obj::new(value, at, &["data", "encoding", "entries", "head"])?;
                let bytes = base64_decode(o.str("data")?).map_err(|e| format!("{at}.data: {e}"))?;
                Ok(JournalData {
                    encoding: JournalEncoding::Base64,
                    bytes,
                    entries: o.u64("entries")?,
                    head: o.hex32("head")?,
                })
            }
            "file" => {
                let o = Obj::new(
                    value,
                    at,
                    &["encoding", "entries", "head", "path", "sha256"],
                )?;
                let path = o.str("path")?;
                if !is_plain_file_name(path) {
                    return Err(format!("{at}.path is not a plain file name"));
                }
                Ok(JournalData {
                    encoding: JournalEncoding::File {
                        path: path.to_string(),
                        sha256: o.hex32("sha256")?,
                    },
                    bytes: Vec::new(),
                    entries: o.u64("entries")?,
                    head: o.hex32("head")?,
                })
            }
            _ => Err(format!("{at}.encoding is neither \"base64\" nor \"file\"")),
        }
    }

    fn to_json(&self) -> Json {
        let mut members = vec![
            ("entries".to_string(), Json::from(self.entries)),
            ("head".to_string(), hex_encode(&self.head).into()),
        ];
        match &self.encoding {
            JournalEncoding::Base64 => {
                members.push(("encoding".into(), "base64".into()));
                members.push(("data".into(), base64_encode(&self.bytes).into()));
            }
            JournalEncoding::File { path, sha256 } => {
                members.push(("encoding".into(), "file".into()));
                members.push(("path".into(), path.as_str().into()));
                members.push(("sha256".into(), hex_encode(sha256).into()));
            }
        }
        Json::Object(members)
    }
}

/// A name with no directory part: never `..`, never a separator, so a
/// bundle cannot point a verifier at a file outside its directory.
fn is_plain_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl Redaction {
    /// No redaction: nothing withheld, no detectors, no patterns.
    pub fn none() -> Redaction {
        Redaction {
            mode: "none".into(),
            detectors: Vec::new(),
            patterns_sha256: patterns_sha256(&[]),
        }
    }

    fn from_json(value: &Json) -> Result<Redaction, String> {
        let at = "bundle.redaction";
        let o = Obj::new(value, at, &["detectors", "mode", "patterns_sha256"])?;
        let mode = o.str("mode")?;
        if !REDACTION_MODES.contains(&mode) {
            return Err(format!(
                "{at}.mode is not one of none, detectors, binary, all"
            ));
        }
        let detectors = o
            .array("detectors")?
            .iter()
            .enumerate()
            .map(|(i, d)| {
                d.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{at}.detectors[{i}] is not a string"))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Redaction {
            mode: mode.to_string(),
            detectors,
            patterns_sha256: o.hex32("patterns_sha256")?,
        })
    }

    fn to_json(&self) -> Json {
        Json::Object(vec![
            (
                "detectors".into(),
                Json::Array(self.detectors.iter().map(|d| d.as_str().into()).collect()),
            ),
            ("mode".into(), self.mode.as_str().into()),
            (
                "patterns_sha256".into(),
                hex_encode(&self.patterns_sha256).into(),
            ),
        ])
    }
}

/// SHA-256 of the canonical JSON array of redaction patterns.
pub fn patterns_sha256(patterns: &[&str]) -> Digest {
    let list = Json::Array(patterns.iter().map(|&p| p.into()).collect());
    sha256(list.canonical_string().as_bytes())
}

impl Anchor {
    fn from_json(value: &Json, at: &str) -> Result<Anchor, String> {
        let o = Obj::new(
            value,
            at,
            &[
                "anchor_digest",
                "checkpoint",
                "consistency_to_latest",
                "inclusion_proof",
                "leaf",
                "leaf_index",
                "root",
                "seq",
                "tree_size",
                "witnesses",
            ],
        )?;
        let leaf =
            crate::encoding::hex_decode(o.str("leaf")?).map_err(|e| format!("{at}.leaf: {e}"))?;
        let witnesses = o
            .array("witnesses")?
            .iter()
            .enumerate()
            .map(|(i, w)| Witness::from_json(w, &format!("{at}.witnesses[{i}]")))
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Anchor {
            seq: o.u64("seq")?,
            tree_size: o.u64("tree_size")?,
            leaf_index: o.u64("leaf_index")?,
            leaf,
            inclusion_proof: o.digests("inclusion_proof")?,
            root: o.hex32("root")?,
            checkpoint: o.str("checkpoint")?.to_string(),
            anchor_digest: o.hex32("anchor_digest")?,
            consistency_to_latest: o.digests("consistency_to_latest")?,
            witnesses,
        })
    }

    fn to_json(&self) -> Json {
        let digests = |d: &[Digest]| Json::Array(d.iter().map(|h| hex_encode(h).into()).collect());
        Json::Object(vec![
            (
                "anchor_digest".into(),
                hex_encode(&self.anchor_digest).into(),
            ),
            ("checkpoint".into(), self.checkpoint.as_str().into()),
            (
                "consistency_to_latest".into(),
                digests(&self.consistency_to_latest),
            ),
            ("inclusion_proof".into(), digests(&self.inclusion_proof)),
            ("leaf".into(), hex_encode(&self.leaf).into()),
            ("leaf_index".into(), self.leaf_index.into()),
            ("root".into(), hex_encode(&self.root).into()),
            ("seq".into(), self.seq.into()),
            ("tree_size".into(), self.tree_size.into()),
            (
                "witnesses".into(),
                Json::Array(self.witnesses.iter().map(Witness::to_json).collect()),
            ),
        ])
    }
}

impl Witness {
    fn from_json(value: &Json, at: &str) -> Result<Witness, String> {
        match value.get("type").and_then(Json::as_str) {
            Some("rfc3161") => {
                let o = Obj::new(
                    value,
                    at,
                    &["certs_pem", "operator", "token", "tsa", "type"],
                )?;
                Ok(Witness::Rfc3161 {
                    tsa: o.str("tsa")?.to_string(),
                    operator: o.str("operator")?.to_string(),
                    token: base64_decode(o.str("token")?)
                        .map_err(|e| format!("{at}.token: {e}"))?,
                    certs_pem: o.str("certs_pem")?.to_string(),
                })
            }
            Some("cosignature") => {
                let o = Obj::new(value, at, &["line", "name", "type"])?;
                Ok(Witness::Cosignature {
                    name: o.str("name")?.to_string(),
                    line: o.str("line")?.to_string(),
                })
            }
            _ => Err(format!(
                "{at}.type is missing or not \"rfc3161\" or \"cosignature\""
            )),
        }
    }

    fn to_json(&self) -> Json {
        match self {
            Witness::Rfc3161 {
                tsa,
                operator,
                token,
                certs_pem,
            } => Json::Object(vec![
                ("certs_pem".into(), certs_pem.as_str().into()),
                ("operator".into(), operator.as_str().into()),
                ("token".into(), base64_encode(token).into()),
                ("tsa".into(), tsa.as_str().into()),
                ("type".into(), "rfc3161".into()),
            ]),
            Witness::Cosignature { name, line } => Json::Object(vec![
                ("line".into(), line.as_str().into()),
                ("name".into(), name.as_str().into()),
                ("type".into(), "cosignature".into()),
            ]),
        }
    }
}

impl VerificationSpec {
    fn from_json(value: &Json) -> Result<VerificationSpec, String> {
        let o = Obj::new(value, "bundle.verification_spec", &["sha256", "url"])?;
        Ok(VerificationSpec {
            url: o.str("url")?.to_string(),
            sha256: o.hex32("sha256")?,
        })
    }

    fn to_json(&self) -> Json {
        Json::Object(vec![
            ("sha256".into(), hex_encode(&self.sha256).into()),
            ("url".into(), self.url.as_str().into()),
        ])
    }
}

impl BundleSignature {
    fn from_json(value: &Json) -> Result<BundleSignature, String> {
        let o = Obj::new(
            value,
            "bundle.signature",
            &["key_id", "public_key", "value"],
        )?;
        Ok(BundleSignature {
            key_id: o.hex::<4>("key_id")?,
            public_key: o.hex32("public_key")?,
            value: o.hex::<64>("value")?,
        })
    }

    fn to_json(&self) -> Json {
        Json::Object(vec![
            ("key_id".into(), hex_encode(&self.key_id).into()),
            ("public_key".into(), hex_encode(&self.public_key).into()),
            ("value".into(), hex_encode(&self.value).into()),
        ])
    }
}

#[cfg(test)]
mod attacks;
#[cfg(test)]
mod tests;
