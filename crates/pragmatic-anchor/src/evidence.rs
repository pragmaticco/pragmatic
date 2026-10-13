//! The anchor section of an evidence bundle for one run (design 5.1): the
//! run's whole leaf chain, each leaf with its inclusion proof, checkpoint,
//! anchor digest, consistency proof to the latest checkpoint and witness
//! objects, plus the latest checkpoint and the run's `anchor_id`.
//!
//! ```json
//! "anchor_id": null,
//! "anchors": [
//!   { "seq": 41, "tree_size": 9001, "leaf_index": 8990, "leaf": "hex",
//!     "inclusion_proof": ["hex"], "root": "hex",
//!     "checkpoint": "signed note text (body + server signature line)",
//!     "anchor_digest": "hex SHA-256 of the checkpoint body",
//!     "consistency_to_latest": ["hex"],
//!     "witnesses": [ { "type": "rfc3161", ... }, { "type": "cosignature", ... } ] } ],
//! "latest_checkpoint": "signed note text"
//! ```
//!
//! - `leaf` is the hex of the full leaf data (design 4.7), from which a
//!   verifier reads the id, entries, head and `prev_leaf_index`, and whose
//!   RFC 6962 leaf hash the inclusion proof starts from.
//! - `anchors` runs from the run's first leaf to its latest; each
//!   `prev_leaf_index` names the previous element's `leaf_index`.
//! - `anchor_id` is `null` when leaves carry plain run ids, and the
//!   lowercase hex of the run's 32-byte anchor salt when they carry HMAC
//!   ids, so the verifier can recompute `HMAC-SHA-256(anchor_id, run_id)`
//!   ([`crate::leaf`]).
//!
//! The bundle builder (the server) places these members in the bundle
//! next to the journal and signs the whole. Everything here is built with
//! the core's strict JSON type, whose canonical form the bundle signature
//! covers.

use pragmatic::encoding::hex_encode;
use pragmatic::json::Json;
use pragmatic::sha256::Digest;

use crate::error::AnchorError;
use crate::leaf::{Leaf, LeafType, RunIdMode};
use crate::log::{hex_list, AnchorLog, WitnessRecord};
use crate::operator::IndependencePolicy;

/// One element of `anchors`.
#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceAnchor {
    pub seq: u64,
    pub tree_size: u64,
    pub leaf_index: u64,
    pub leaf: Leaf,
    pub inclusion_proof: Vec<Digest>,
    pub root: Digest,
    /// The signed checkpoint note.
    pub checkpoint: String,
    pub anchor_digest: Digest,
    pub consistency_to_latest: Vec<Digest>,
    pub witnesses: Vec<WitnessRecord>,
    /// Whether the stored witnesses meet the independence policy. Not part
    /// of the bundle: the verifier decides from its own pinned roots.
    pub independent: bool,
}

impl EvidenceAnchor {
    /// The element in the design 5.1 shape (no other keys).
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("seq".into(), self.seq.into()),
            ("tree_size".into(), self.tree_size.into()),
            ("leaf_index".into(), self.leaf_index.into()),
            ("leaf".into(), hex_encode(&self.leaf.encode()).into()),
            ("inclusion_proof".into(), hex_list(&self.inclusion_proof)),
            ("root".into(), hex_encode(&self.root).into()),
            ("checkpoint".into(), self.checkpoint.as_str().into()),
            (
                "anchor_digest".into(),
                hex_encode(&self.anchor_digest).into(),
            ),
            (
                "consistency_to_latest".into(),
                hex_list(&self.consistency_to_latest),
            ),
            (
                "witnesses".into(),
                Json::Array(self.witnesses.iter().map(|w| w.object.clone()).collect()),
            ),
        ])
    }
}

/// The anchor section for one run.
#[derive(Clone, Debug, PartialEq)]
pub struct AnchorSection {
    /// The run's anchor salt under HMAC ids; `None` for plain ids.
    pub anchor_id: Option<[u8; 32]>,
    /// The leaf chain, oldest first.
    pub anchors: Vec<EvidenceAnchor>,
    /// The latest checkpoint's signed note, if the log has one.
    pub latest_checkpoint: Option<String>,
    /// The latest checkpoint's tree size.
    pub latest_tree_size: u64,
}

impl AnchorSection {
    /// `anchor_id`: `null` or the salt as lowercase hex.
    pub fn anchor_id_json(&self) -> Json {
        self.anchor_id.map_or(Json::Null, |s| hex_encode(&s).into())
    }

    /// `anchors`.
    pub fn anchors_json(&self) -> Json {
        Json::Array(self.anchors.iter().map(EvidenceAnchor::to_json).collect())
    }

    /// `latest_checkpoint`: the signed note, or `null` for a log with no
    /// checkpoint yet.
    pub fn latest_checkpoint_json(&self) -> Json {
        self.latest_checkpoint
            .as_deref()
            .map_or(Json::Null, Json::from)
    }

    /// The three bundle members this section supplies, in bundle order.
    pub fn bundle_members(&self) -> Vec<(String, Json)> {
        vec![
            ("anchor_id".into(), self.anchor_id_json()),
            ("anchors".into(), self.anchors_json()),
            ("latest_checkpoint".into(), self.latest_checkpoint_json()),
        ]
    }

    /// The journal length covered by the newest independently anchored
    /// leaf (the run's `anchored_entries` as this log sees it).
    pub fn anchored_entries(&self) -> u64 {
        self.anchors
            .iter()
            .filter(|a| a.independent)
            .map(|a| a.leaf.entries)
            .max()
            .unwrap_or(0)
    }
}

/// Build the anchor section of `id` from `log`.
pub fn anchor_section(
    log: &AnchorLog,
    id_mode: &RunIdMode,
    policy: &IndependencePolicy,
    leaf_type: LeafType,
    id: &str,
) -> Result<AnchorSection, AnchorError> {
    let latest = log.latest_checkpoint();
    let latest_tree_size = latest.map_or(0, |c| c.tree_size);
    let latest_checkpoint = match latest {
        Some(c) => Some(log.checkpoint(c.seq)?.signed.note),
        None => None,
    };
    let leaf_id = id_mode.leaf_id(leaf_type, id);
    let mut anchors = Vec::new();
    for (leaf_index, leaf) in log.leaf_chain(leaf_type, &leaf_id)? {
        let meta = log.checkpoint_for_leaf(leaf_index).ok_or_else(|| {
            AnchorError::Corrupt(format!("leaf {leaf_index} is in no checkpoint"))
        })?;
        let stored = log.checkpoint(meta.seq)?;
        let witnesses = log.witnesses(meta.seq)?;
        anchors.push(EvidenceAnchor {
            seq: meta.seq,
            tree_size: meta.tree_size,
            leaf_index,
            inclusion_proof: log.inclusion_proof(leaf_index, meta.tree_size)?,
            root: meta.root,
            checkpoint: stored.signed.note,
            anchor_digest: stored.signed.anchor_digest,
            consistency_to_latest: log.consistency_proof(meta.tree_size, latest_tree_size)?,
            independent: policy.is_independent(witnesses.iter().map(|w| w.operator.as_str())),
            witnesses,
            leaf,
        });
    }
    Ok(AnchorSection {
        anchor_id: id_mode.salt(leaf_type, id),
        anchors,
        latest_checkpoint,
        latest_tree_size,
    })
}
