//! Anchor log leaves (design 4.7): what one leaf commits to, its exact
//! byte encoding, and how a run id becomes the id inside a leaf.
//!
//! ```text
//! leaf_data = "pragmatic/v2/leaf" ‖ u8 type (0 run, 1 access log) ‖
//!             u32 len(id) ‖ id ‖ u64 entries ‖ head(32) ‖
//!             u64 prev_leaf_index (u64::MAX if none)
//! ```
//!
//! Integers are little-endian, like every integer in journal format 2. The
//! Merkle leaf hash is the RFC 6962 one, `SHA-256(0x00 ‖ leaf_data)`
//! ([`pragmatic::merkle::leaf_hash`]), so the domain prefix inside the
//! data separates Pragmatic leaves from any other log's, and the `0x00`
//! separates leaves from interior nodes.
//!
//! `prev_leaf_index` links a run's leaves into a chain. An evidence bundle
//! carries the whole chain, and a verifier holding the full log (`--log`)
//! can check that no leaf of the run was left out: every leaf names its
//! predecessor, so a bundle that skipped one would break the chain.
//!
//! # Run ids in leaves
//!
//! With `anchor_run_ids = "plain"` the id is the run id's UTF-8 bytes. With
//! `"hmac"` it is `HMAC-SHA-256(anchor_salt, run_id)`, so the anchor log
//! (which auditors of one run may download whole, to check for hidden
//! anchors) does not reveal the ids of other runs. The salt is per run,
//! derived from one server secret:
//!
//! ```text
//! anchor_salt = HMAC-SHA-256(anchor_key, "pragmatic/v2/anchor-salt" ‖ run_id)
//! id          = HMAC-SHA-256(anchor_salt, run_id)
//! ```
//!
//! A bundle for one run carries that run's salt (the bundle's `anchor_id`),
//! which lets its auditor recompute the id and nothing else: knowing one
//! run's salt says nothing about another run's, so the log's other ids stay
//! opaque even to someone who guesses candidate run ids.

use pragmatic::merkle;
use pragmatic::sha256::{hmac_sha256, Digest, Sha256};

use crate::error::AnchorError;

/// The domain prefix that starts every leaf's data.
pub const LEAF_PREFIX: &[u8] = b"pragmatic/v2/leaf";

/// `prev_leaf_index` of a run's first leaf.
pub const NO_PREV: u64 = u64::MAX;

/// The longest id a leaf may carry. Run ids are at most 200 bytes (design
/// 2.15) and HMAC ids 32; the margin leaves room for future leaf types
/// without letting a damaged length field ask for gigabytes.
pub const MAX_ID_LEN: usize = 1024;

/// The id of the server's access log (`audit/access.journal`) in its leaves.
/// The type byte already separates it from runs; the id leaves room for a
/// second access log (after a rotation, say) without a format change.
pub const ACCESS_LOG_ID: &[u8] = b"access";

/// The run id under which a server in witness mode keeps its own journal of
/// cosigned checkpoints (design 4.8). The `pragmatic:` prefix is reserved
/// (design 2.15), so no client run can collide with it.
pub const WITNESS_RUN_ID: &str = "pragmatic:witness";

/// Domain separation for per-run anchor salts.
const SALT_DOMAIN: &[u8] = b"pragmatic/v2/anchor-salt";

/// Bytes in a leaf besides its id: prefix, type, id length, entries, head
/// and previous index.
const FIXED_LEN: usize = LEAF_PREFIX.len() + 1 + 4 + 8 + 32 + 8;

/// The longest leaf encoding: [`FIXED_LEN`] plus [`MAX_ID_LEN`].
pub const MAX_LEAF_LEN: usize = FIXED_LEN + MAX_ID_LEN;

/// What a leaf anchors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeafType {
    /// A run's journal (type byte 0).
    Run,
    /// The server's access log (type byte 1).
    AccessLog,
}

impl LeafType {
    /// The type byte in the leaf encoding.
    pub fn byte(self) -> u8 {
        match self {
            LeafType::Run => 0,
            LeafType::AccessLog => 1,
        }
    }

    /// The type for a type byte, if it is one the format defines.
    pub fn from_byte(b: u8) -> Option<LeafType> {
        match b {
            0 => Some(LeafType::Run),
            1 => Some(LeafType::AccessLog),
            _ => None,
        }
    }

    /// The name used in JSON documents: `"run"` or `"access_log"`.
    pub fn name(self) -> &'static str {
        match self {
            LeafType::Run => "run",
            LeafType::AccessLog => "access_log",
        }
    }

    /// The type for a JSON name.
    pub fn from_name(name: &str) -> Option<LeafType> {
        match name {
            "run" => Some(LeafType::Run),
            "access_log" => Some(LeafType::AccessLog),
            _ => None,
        }
    }
}

/// One leaf of the anchor log: a claim that the journal `id` had `entries`
/// entries with chain head `head`, linked to the same id's previous leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub leaf_type: LeafType,
    /// The id as it appears in the leaf: plain run id bytes, an HMAC id
    /// (see the module documentation), or [`ACCESS_LOG_ID`].
    pub id: Vec<u8>,
    /// The journal's entry count when it was snapshotted.
    pub entries: u64,
    /// The journal's chain head after `entries` entries (the genesis value
    /// for an empty journal, design 2.1).
    pub head: Digest,
    /// The index of the previous leaf with the same type and id, or `None`
    /// for the first one (encoded as [`NO_PREV`]).
    pub prev_leaf_index: Option<u64>,
}

impl Leaf {
    /// The leaf's bytes, exactly as the design's `leaf_data`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FIXED_LEN + self.id.len());
        out.extend_from_slice(LEAF_PREFIX);
        out.push(self.leaf_type.byte());
        out.extend_from_slice(&(self.id.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.entries.to_le_bytes());
        out.extend_from_slice(&self.head);
        out.extend_from_slice(&self.prev_leaf_index.unwrap_or(NO_PREV).to_le_bytes());
        out
    }

    /// Decode leaf bytes, accepting only what [`Leaf::encode`] produces:
    /// the prefix, a known type, a non-empty id of at most [`MAX_ID_LEN`]
    /// bytes, and no bytes after the previous index.
    pub fn decode(bytes: &[u8]) -> Result<Leaf, AnchorError> {
        let bad = |why: &str| AnchorError::InvalidLeaf(why.to_string());
        let rest = bytes
            .strip_prefix(LEAF_PREFIX)
            .ok_or_else(|| bad("missing the pragmatic/v2/leaf prefix"))?;
        let (&type_byte, rest) = rest.split_first().ok_or_else(|| bad("truncated"))?;
        let leaf_type = LeafType::from_byte(type_byte).ok_or_else(|| bad("unknown type"))?;
        let (len, rest) = split_le_u32(rest).ok_or_else(|| bad("truncated"))?;
        let len = len as usize;
        if len == 0 || len > MAX_ID_LEN {
            return Err(bad("id length out of range"));
        }
        if rest.len() != len + 8 + 32 + 8 {
            return Err(bad("length does not match the id length"));
        }
        let (id, rest) = rest.split_at(len);
        let (entries, rest) = split_le_u64(rest).expect("length checked");
        let head: Digest = rest[..32].try_into().expect("length checked");
        let (prev, _) = split_le_u64(&rest[32..]).expect("length checked");
        Ok(Leaf {
            leaf_type,
            id: id.to_vec(),
            entries,
            head,
            prev_leaf_index: (prev != NO_PREV).then_some(prev),
        })
    }

    /// The RFC 6962 leaf hash of the encoding.
    pub fn hash(&self) -> Digest {
        merkle::leaf_hash(&self.encode())
    }

    /// The key leaves are ordered by within a batch: type byte, then raw id
    /// bytes (design 4.7).
    pub fn order_key(&self) -> (u8, &[u8]) {
        (self.leaf_type.byte(), &self.id)
    }
}

/// A fixed-size key for a `(type, id)` pair: `SHA-256(type ‖ u32 len ‖ id)`.
/// The log keeps one map entry per id it has seen, and a run id can be 200
/// bytes, so the map holds this digest instead of the id.
pub fn id_key(leaf_type: LeafType, id: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(&[leaf_type.byte()]);
    h.update(&(id.len() as u32).to_le_bytes());
    h.update(id);
    h.finalize()
}

fn split_le_u32(b: &[u8]) -> Option<(u32, &[u8])> {
    if b.len() < 4 {
        return None;
    }
    let (n, rest) = b.split_at(4);
    Some((u32::from_le_bytes(n.try_into().ok()?), rest))
}

fn split_le_u64(b: &[u8]) -> Option<(u64, &[u8])> {
    if b.len() < 8 {
        return None;
    }
    let (n, rest) = b.split_at(8);
    Some((u64::from_le_bytes(n.try_into().ok()?), rest))
}

/// How run ids appear in leaves (`[anchoring] anchor_run_ids`).
#[derive(Clone, Default)]
pub enum RunIdMode {
    /// The run id's UTF-8 bytes (the default).
    #[default]
    Plain,
    /// `HMAC-SHA-256(anchor_salt, run_id)` with a per-run salt derived from
    /// `key` (see the module documentation).
    Hmac { key: [u8; 32] },
}

impl std::fmt::Debug for RunIdMode {
    /// Never prints the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunIdMode::Plain => f.write_str("Plain"),
            RunIdMode::Hmac { .. } => f.write_str("Hmac { .. }"),
        }
    }
}

impl RunIdMode {
    /// The id a leaf carries for `run_id`. Only runs are mapped; any other
    /// type's id is used as it is.
    pub fn leaf_id(&self, leaf_type: LeafType, run_id: &str) -> Vec<u8> {
        match (self, leaf_type) {
            (RunIdMode::Hmac { key }, LeafType::Run) => {
                hmac_run_id(&anchor_salt(key, run_id), run_id).to_vec()
            }
            _ => run_id.as_bytes().to_vec(),
        }
    }

    /// The per-run salt an evidence bundle carries as `anchor_id`, or
    /// `None` when ids are plain (or the leaf is not a run's).
    pub fn salt(&self, leaf_type: LeafType, run_id: &str) -> Option<[u8; 32]> {
        match (self, leaf_type) {
            (RunIdMode::Hmac { key }, LeafType::Run) => Some(anchor_salt(key, run_id)),
            _ => None,
        }
    }
}

/// The per-run anchor salt: `HMAC-SHA-256(key, "pragmatic/v2/anchor-salt" ‖
/// run_id)`.
pub fn anchor_salt(key: &[u8; 32], run_id: &str) -> [u8; 32] {
    let mut msg = Vec::with_capacity(SALT_DOMAIN.len() + run_id.len());
    msg.extend_from_slice(SALT_DOMAIN);
    msg.extend_from_slice(run_id.as_bytes());
    hmac_sha256(key, &msg)
}

/// A run's id in leaves under `anchor_run_ids = "hmac"`:
/// `HMAC-SHA-256(salt, run_id)`. This is what a verifier recomputes from a
/// bundle's `anchor_id` and `run_id`.
pub fn hmac_run_id(salt: &[u8; 32], run_id: &str) -> [u8; 32] {
    hmac_sha256(salt, run_id.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pragmatic::encoding::{hex_decode, hex_encode};

    fn sample() -> Leaf {
        Leaf {
            leaf_type: LeafType::Run,
            id: b"run-1".to_vec(),
            entries: 57,
            head: [0xab; 32],
            prev_leaf_index: None,
        }
    }

    /// The exact bytes of a leaf, field by field, so an independent
    /// implementation (the Python reference verifier, an auditor's script)
    /// can be checked against the same vector.
    #[test]
    fn encoding_vector_first_leaf() {
        let expected = concat!(
            "707261676d617469632f76322f6c656166", // "pragmatic/v2/leaf"
            "00",                                 // type: run
            "05000000",                           // u32 LE id length
            "72756e2d31",                         // "run-1"
            "3900000000000000",                   // u64 LE entries = 57
            "abababababababababababababababababababababababababababababababab",
            "ffffffffffffffff", // no previous leaf
        );
        let leaf = sample();
        assert_eq!(hex_encode(&leaf.encode()), expected);
        assert_eq!(Leaf::decode(&hex_decode(expected).unwrap()).unwrap(), leaf);
        // The Merkle leaf hash is SHA-256(0x00 ‖ leaf_data); the hex was
        // computed independently with Python's hashlib.
        let mut prefixed = vec![0u8];
        prefixed.extend_from_slice(&leaf.encode());
        assert_eq!(leaf.hash(), pragmatic::sha256::sha256(&prefixed));
        assert_eq!(
            hex_encode(&leaf.hash()),
            "af080bd39df677fbdfa530c8fc6d2b8c56955033aa5b7520cf949457ee272d81"
        );
    }

    #[test]
    fn encoding_vector_access_log_with_previous() {
        let leaf = Leaf {
            leaf_type: LeafType::AccessLog,
            id: ACCESS_LOG_ID.to_vec(),
            entries: 0x0102_0304_0506_0708,
            head: [0u8; 32],
            prev_leaf_index: Some(258),
        };
        let expected = concat!(
            "707261676d617469632f76322f6c656166",
            "01",
            "06000000",
            "616363657373", // "access"
            "0807060504030201",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0201000000000000", // 258
        );
        assert_eq!(hex_encode(&leaf.encode()), expected);
        assert_eq!(Leaf::decode(&leaf.encode()).unwrap(), leaf);
    }

    #[test]
    fn decode_rejects_everything_encode_cannot_produce() {
        let good = sample().encode();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", vec![]),
            ("wrong prefix", {
                let mut b = good.clone();
                b[0] ^= 1;
                b
            }),
            ("unknown type", {
                let mut b = good.clone();
                b[LEAF_PREFIX.len()] = 2;
                b
            }),
            ("trailing byte", {
                let mut b = good.clone();
                b.push(0);
                b
            }),
            ("short", good[..good.len() - 1].to_vec()),
            ("zero-length id", {
                Leaf {
                    id: vec![],
                    ..sample()
                }
                .encode()
            }),
            ("id over the limit", {
                Leaf {
                    id: vec![b'a'; MAX_ID_LEN + 1],
                    ..sample()
                }
                .encode()
            }),
            ("length field larger than the data", {
                let mut b = good.clone();
                b[LEAF_PREFIX.len() + 1] = 200;
                b
            }),
        ];
        for (what, bytes) in cases {
            assert!(Leaf::decode(&bytes).is_err(), "{what} was accepted");
        }
        // The longest id is accepted.
        let long = Leaf {
            id: vec![b'a'; MAX_ID_LEN],
            ..sample()
        };
        assert_eq!(long.encode().len(), MAX_LEAF_LEN);
        assert_eq!(Leaf::decode(&long.encode()).unwrap(), long);
    }

    #[test]
    fn hmac_ids_use_a_per_run_salt() {
        let mode = RunIdMode::Hmac { key: [7u8; 32] };
        let a = mode.leaf_id(LeafType::Run, "run-a");
        let b = mode.leaf_id(LeafType::Run, "run-b");
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        // The bundle's salt recomputes the id, as a verifier would.
        let salt = mode.salt(LeafType::Run, "run-a").unwrap();
        assert_eq!(hmac_run_id(&salt, "run-a").to_vec(), a);
        // One run's salt does not produce another run's id.
        assert_ne!(hmac_run_id(&salt, "run-b").to_vec(), b);
        // The access log keeps its plain id; plain mode leaves ids alone.
        assert_eq!(mode.leaf_id(LeafType::AccessLog, "access"), b"access");
        assert_eq!(mode.salt(LeafType::AccessLog, "access"), None);
        assert_eq!(RunIdMode::Plain.leaf_id(LeafType::Run, "run-a"), b"run-a");
        assert_eq!(RunIdMode::Plain.salt(LeafType::Run, "run-a"), None);
        assert_eq!(format!("{mode:?}"), "Hmac { .. }");
    }

    #[test]
    fn hmac_vector() {
        // Fixed inputs, so other implementations can check the derivation.
        let key = [0x11u8; 32];
        let salt = anchor_salt(&key, "user.42");
        let id = hmac_run_id(&salt, "user.42");
        assert_eq!(
            salt,
            hmac_sha256(&key, b"pragmatic/v2/anchor-saltuser.42"),
            "salt = HMAC(key, domain ‖ run_id)"
        );
        assert_eq!(id, hmac_sha256(&salt, b"user.42"));
    }

    #[test]
    fn ordering_is_type_then_raw_id_bytes() {
        let mk = |t, id: &[u8]| Leaf {
            leaf_type: t,
            id: id.to_vec(),
            ..sample()
        };
        let mut leaves = [
            mk(LeafType::AccessLog, b"access"),
            mk(LeafType::Run, b"b"),
            mk(LeafType::Run, b"a\xff"),
            mk(LeafType::Run, b"ab"),
            mk(LeafType::Run, b"a"),
        ];
        leaves.sort_by(|x, y| x.order_key().cmp(&y.order_key()));
        let order: Vec<&[u8]> = leaves.iter().map(|l| &l.id[..]).collect();
        assert_eq!(
            order,
            vec![&b"a"[..], b"ab", b"a\xff", b"b", b"access"],
            "runs first, ids compared as raw bytes"
        );
    }
}
