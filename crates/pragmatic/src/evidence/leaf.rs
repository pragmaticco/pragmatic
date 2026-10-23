//! Anchor log leaves and the logs an auditor checks a bundle against
//! (design 4.7 and 5.3 step 11).
//!
//! Stet Server keeps one append-only RFC 6962 Merkle log. Each leaf
//! commits to one run's (or the access log's) journal prefix:
//!
//! ```text
//! leaf_data = "pragmatic/v2/leaf" ‖ u8 type ‖ u32 len(id) ‖ id ‖
//!             u64 entries ‖ head (32 bytes) ‖ u64 prev_leaf_index
//! ```
//!
//! Integers are little-endian, like every integer in the journal format.
//! `type` is 0 for a run and 1 for the access log; `prev_leaf_index` is the
//! index of the same id's previous leaf, or `u64::MAX` for its first, which
//! links a run's leaves into a chain a bundle must carry whole.
//!
//! The run is named by its id (`anchor_run_ids = "plain"`), or by
//! `HMAC-SHA-256(k_run, run_id)` with a per-run key `k_run` that the bundle
//! carries as `anchor_id` (`"hmac"`), so a witness or a log reader never
//! learns run ids while an auditor holding the bundle can still recompute
//! the leaf.

use crate::encoding::{hex_decode, hex_encode};
use crate::json::Json;
use crate::note::Note;
use crate::sha256::{hmac_sha256, Digest, DIGEST_LEN};

/// Domain-separation tag at the start of every leaf.
pub const LEAF_TAG: &[u8] = b"pragmatic/v2/leaf";
/// `type` of a run's leaf.
pub const LEAF_RUN: u8 = 0;
/// `type` of the access log's leaf.
pub const LEAF_ACCESS_LOG: u8 = 1;
/// `prev_leaf_index` of an id's first leaf.
pub const NO_PREVIOUS: u64 = u64::MAX;
/// The longest id a leaf may carry. A run id is at most 200 bytes and an
/// HMAC id 32, so anything longer is malformed. An id is never empty: run
/// ids are not, the access log's is `access`, and the anchoring library
/// refuses to write an empty one, so an empty id can only be forged.
pub const MAX_LEAF_ID: usize = 1024;

/// One decoded anchor log leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    /// [`LEAF_RUN`] or [`LEAF_ACCESS_LOG`].
    pub kind: u8,
    /// The run id bytes, or its HMAC form.
    pub id: Vec<u8>,
    /// The journal prefix length this leaf anchors.
    pub entries: u64,
    /// The chain head after `entries` entries.
    pub head: Digest,
    /// The id's previous leaf, `None` for its first.
    pub prev_leaf_index: Option<u64>,
}

impl Leaf {
    /// The leaf data bytes (what [`crate::merkle::leaf_hash`] hashes).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LEAF_TAG.len() + 1 + 4 + self.id.len() + 8 + 32 + 8);
        out.extend_from_slice(LEAF_TAG);
        out.push(self.kind);
        out.extend_from_slice(&(self.id.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.entries.to_le_bytes());
        out.extend_from_slice(&self.head);
        out.extend_from_slice(&self.prev_leaf_index.unwrap_or(NO_PREVIOUS).to_le_bytes());
        out
    }

    /// Decode leaf data exactly: the tag, a known type, an id of 1 to
    /// [`MAX_LEAF_ID`] bytes, and nothing after the last field.
    pub fn decode(data: &[u8]) -> Result<Leaf, &'static str> {
        let rest = data
            .strip_prefix(LEAF_TAG)
            .ok_or("leaf does not start with the pragmatic/v2/leaf tag")?;
        let (&kind, rest) = rest.split_first().ok_or("leaf ends early")?;
        if kind != LEAF_RUN && kind != LEAF_ACCESS_LOG {
            return Err("leaf has an unknown type");
        }
        let (len, rest) = take::<4>(rest)?;
        let len = u32::from_le_bytes(len) as usize;
        if len == 0 || len > MAX_LEAF_ID || len > rest.len() {
            return Err("leaf id length is out of range");
        }
        let (id, rest) = rest.split_at(len);
        let (entries, rest) = take::<8>(rest)?;
        let (head, rest) = take::<DIGEST_LEN>(rest)?;
        let (prev, rest) = take::<8>(rest)?;
        if !rest.is_empty() {
            return Err("leaf has trailing bytes");
        }
        let prev = u64::from_le_bytes(prev);
        Ok(Leaf {
            kind,
            id: id.to_vec(),
            entries: u64::from_le_bytes(entries),
            head,
            prev_leaf_index: (prev != NO_PREVIOUS).then_some(prev),
        })
    }
}

fn take<const N: usize>(bytes: &[u8]) -> Result<([u8; N], &[u8]), &'static str> {
    if bytes.len() < N {
        return Err("leaf ends early");
    }
    let (head, rest) = bytes.split_at(N);
    Ok((head.try_into().expect("length checked"), rest))
}

/// The id a run's leaves carry: the run id's bytes, or
/// `HMAC-SHA-256(k_run, run_id)` when the bundle names a per-run key.
pub fn leaf_id(run_id: &str, anchor_key: Option<&[u8; 32]>) -> Vec<u8> {
    match anchor_key {
        None => run_id.as_bytes().to_vec(),
        Some(k) => hmac_sha256(k, run_id.as_bytes()).to_vec(),
    }
}

/// A full copy of the anchor log, as `GET /v1/anchors/log` returns it to an
/// administrator: every leaf from index 0, in order.
///
/// File form (strict JSON): `{"leaves": ["<hex leaf data>", ...]}`.
/// Completeness is what makes it useful: with every leaf in hand, an
/// auditor recomputes the root of the bundle's latest checkpoint and then
/// knows every leaf the log holds for the run, so a bundle that leaves an
/// anchor out is caught.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnchorLog {
    /// Leaf data by index.
    pub leaves: Vec<Vec<u8>>,
}

impl AnchorLog {
    /// Parse the file form. Unknown keys are rejected.
    pub fn from_json(bytes: &[u8]) -> Result<AnchorLog, String> {
        let doc = Json::parse_bytes(bytes).map_err(|e| e.to_string())?;
        let members = doc.as_object().ok_or("anchor log is not a JSON object")?;
        if members.len() != 1 || members[0].0 != "leaves" {
            return Err("anchor log must have exactly the key \"leaves\"".into());
        }
        let items = members[0]
            .1
            .as_array()
            .ok_or("\"leaves\" is not an array")?;
        let mut leaves = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            let text = item
                .as_str()
                .ok_or_else(|| format!("leaf {i} is not a string"))?;
            leaves.push(hex_decode(text).map_err(|e| format!("leaf {i}: {e}"))?);
        }
        Ok(AnchorLog { leaves })
    }

    /// The file form.
    pub fn to_json(&self) -> String {
        let leaves = self
            .leaves
            .iter()
            .map(|l| Json::from(hex_encode(l)))
            .collect();
        Json::Object(vec![("leaves".into(), Json::Array(leaves))]).to_string()
    }
}

/// A witness's record of the checkpoints it cosigned for one log, as
/// `GET /v1/witness/log/{origin}` returns it.
///
/// File form (strict JSON): `{"witness": "<cosigner name>", "origin":
/// "<log origin>", "checkpoints": ["<signed note>", ...]}`. A witness
/// cosigns at most one root per tree size, so a bundle checkpoint with the
/// same size and another root shows the log presented two histories.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessLog {
    /// The cosigner name the witness signs as.
    pub witness: String,
    /// The log origin the history is for.
    pub origin: String,
    /// The cosigned checkpoints, parsed.
    pub checkpoints: Vec<Note>,
}

impl WitnessLog {
    /// Parse the file form. Unknown keys are rejected.
    pub fn from_json(bytes: &[u8]) -> Result<WitnessLog, String> {
        let doc = Json::parse_bytes(bytes).map_err(|e| e.to_string())?;
        let members = doc.as_object().ok_or("witness log is not a JSON object")?;
        let mut keys: Vec<&str> = members.iter().map(|(k, _)| k.as_str()).collect();
        keys.sort_unstable();
        if keys != ["checkpoints", "origin", "witness"] {
            return Err(
                "witness log must have exactly the keys \"checkpoints\", \"origin\" and \"witness\""
                    .into(),
            );
        }
        let text = |k: &str| {
            doc.get(k)
                .and_then(Json::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("\"{k}\" is not a string"))
        };
        let items = doc
            .get("checkpoints")
            .and_then(Json::as_array)
            .ok_or("\"checkpoints\" is not an array")?;
        let mut checkpoints = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            let note = item
                .as_str()
                .ok_or_else(|| format!("checkpoint {i} is not a string"))?;
            checkpoints.push(Note::parse(note).map_err(|e| format!("checkpoint {i}: {e}"))?);
        }
        Ok(WitnessLog {
            witness: text("witness")?,
            origin: text("origin")?,
            checkpoints,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf() -> Leaf {
        Leaf {
            kind: LEAF_RUN,
            id: b"run-1".to_vec(),
            entries: 7,
            head: [9; 32],
            prev_leaf_index: Some(3),
        }
    }

    #[test]
    fn leaves_round_trip_exactly() {
        let l = leaf();
        let data = l.encode();
        assert_eq!(Leaf::decode(&data).unwrap(), l);
        let first = Leaf {
            prev_leaf_index: None,
            ..leaf()
        };
        let data = first.encode();
        assert_eq!(&data[data.len() - 8..], &[0xff; 8]);
        assert_eq!(Leaf::decode(&data).unwrap(), first);
    }

    #[test]
    fn malformed_leaves_are_rejected() {
        let data = leaf().encode();
        let mut extra = data.clone();
        extra.push(0);
        assert!(Leaf::decode(&extra).is_err());
        assert!(Leaf::decode(&data[..data.len() - 1]).is_err());
        let mut kind = data.clone();
        kind[LEAF_TAG.len()] = 2;
        assert!(Leaf::decode(&kind).is_err());
        let mut tag = data.clone();
        tag[0] ^= 1;
        assert!(Leaf::decode(&tag).is_err());
        let mut len = data;
        len[LEAF_TAG.len() + 1] = 0xff;
        assert!(Leaf::decode(&len).is_err());
        let empty = Leaf {
            id: Vec::new(),
            ..leaf()
        };
        assert!(
            Leaf::decode(&empty.encode()).is_err(),
            "an empty id is refused, as the anchoring library refuses to write one"
        );
    }

    #[test]
    fn hmac_ids() {
        assert_eq!(leaf_id("r", None), b"r");
        let key = [1u8; 32];
        assert_eq!(leaf_id("r", Some(&key)), hmac_sha256(&key, b"r").to_vec());
    }

    #[test]
    fn log_files() {
        let log = AnchorLog {
            leaves: vec![leaf().encode(), b"x".to_vec()],
        };
        assert_eq!(AnchorLog::from_json(log.to_json().as_bytes()).unwrap(), log);
        assert!(AnchorLog::from_json(br#"{"leaves":[],"extra":1}"#).is_err());
        assert!(AnchorLog::from_json(br#"{"leaves":["AB"]}"#).is_err());
        assert!(WitnessLog::from_json(br#"{"witness":"w","origin":"o","checkpoints":[]}"#).is_ok());
        assert!(WitnessLog::from_json(br#"{"witness":"w","origin":"o"}"#).is_err());
        assert!(
            WitnessLog::from_json(br#"{"witness":"w","origin":"o","checkpoints":["x"]}"#).is_err()
        );
    }
}
