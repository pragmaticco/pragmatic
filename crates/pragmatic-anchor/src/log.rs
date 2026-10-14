//! The cumulative anchor log on disk (design 4.2 and 4.7): one append-only
//! RFC 6962 Merkle log of [`Leaf`]s, one signed checkpoint per batch, and
//! the witness results each checkpoint collects.
//!
//! # Layout
//!
//! ```text
//! <data_dir>/anchors/
//!   log.leaves                     header, then u32 LE len ‖ leaf_data per leaf
//!   sth/<seq 20-digit>.json        one checkpoint per batch; create_new, never overwritten
//!   batches/<seq 20-digit>.json    which run each leaf of the batch belongs to (never served)
//!   witness/<seq 20-digit>/<label>.json
//!                                  one verified witness result per witness, create_new
//! ```
//!
//! `log.leaves` starts with a 16-byte header (`PRAGLEAF`, u32 LE version 1,
//! u32 LE flags 0). Leaves are only ever appended, in whole batches.
//!
//! # Commit order and recovery
//!
//! A batch is committed by, in order: appending its leaves and fsyncing
//! the leaves file, writing its batch index, then publishing its
//! checkpoint file (each fsynced with its directory). The checkpoint file
//! is the commit point: the latest checkpoint's tree size says how many
//! leaves are real.
//!
//! Checkpoint files and witness results are *published*: written under a
//! temporary name, fsynced, then linked to their real name, which never
//! replaces a file. A crash therefore leaves either no checkpoint file or
//! a complete one, never a torn one, and a checkpoint file that does not
//! parse can only have been damaged after it was written.
//!
//! At startup ([`AnchorLog::open`]):
//!
//! - the `sth/` and `batches/` directories are fsynced first, so every
//!   file recovery reads is durable before anything is built on it, and
//!   temporary files left by a crash are removed;
//! - a witness result directory for a sequence number with no checkpoint
//!   file at or past the latest is [`AnchorError::Corrupt`]: witnesses are
//!   asked only after a checkpoint is durable, so that checkpoint was
//!   committed and published, and recovering past it would sign a second,
//!   different tree under its sequence number (a fork) and throw away the
//!   third parties' evidence. Witness results are never deleted;
//! - any checkpoint file that does not parse, a leaf inside the
//!   checkpointed prefix that does not decode, a root the leaves do not
//!   reproduce or a broken `prev_leaf_index` chain is likewise
//!   [`AnchorError::Corrupt`], never repaired;
//! - leaves past the latest checkpoint were never signed or shown to
//!   anyone (a crash before the checkpoint was published). They are moved
//!   aside to `log.leaves.uncommitted-<unix ms>` and the file is
//!   truncated. Batch indexes newer than the latest checkpoint are
//!   removed, and the next sequence number is the latest one plus one.
//!
//! Nothing is moved or removed until every check has passed, so a log
//! refused as corrupt is left exactly as it was found.
//!
//! Every checkpoint's root is recomputed from the leaves while they are
//! read, so a damaged leaf, or a checkpoint file edited to claim another
//! root, is found at startup rather than by an auditor.
//!
//! # Failed writes
//!
//! A batch that fails before its checkpoint file is published is rolled
//! back. One whose checkpoint file was published but whose directory
//! fsync failed may or may not survive a crash, so it is *not* rolled
//! back (truncating the leaves under a checkpoint that may persist would
//! leave a log that can never be opened again): the log is poisoned
//! instead and refuses writes until [`AnchorLog::reopen`], whose recovery
//! settles the question either way. The checkpoint is never shown to a
//! witness before then.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use pragmatic::encoding::hex_encode;
use pragmatic::json::Json;
use pragmatic::merkle;
use pragmatic::sha256::Digest;

use crate::checkpoint::{json_hex, json_str, json_u64, LogSigner, SignedCheckpoint};
use crate::error::AnchorError;
use crate::fsutil::{
    create_new_durable, ensure_dir, parse_seq_name, publish_new_durable, read_exact_at,
    remove_temp_files, seq_name, sync_dir, unix_millis, write_atomic,
};
use crate::leaf::{id_key, Leaf, LeafType, MAX_ID_LEN, MAX_LEAF_LEN};
use crate::tree::{LeafHashSource, NoSource, TreeCache, DEFAULT_CHUNK_BITS};

/// The leaves file, relative to the anchors directory.
pub const LEAVES_FILE: &str = "log.leaves";
/// The checkpoint directory.
pub const STH_DIR: &str = "sth";
/// The batch index directory.
pub const BATCH_DIR: &str = "batches";
/// The witness result directory.
pub const WITNESS_DIR: &str = "witness";

const LEAVES_MAGIC: &[u8; 8] = b"PRAGLEAF";
const LEAVES_VERSION: u32 = 1;
const LEAVES_HEADER_LEN: u64 = 16;

fn leaves_header() -> [u8; LEAVES_HEADER_LEN as usize] {
    let mut h = [0u8; LEAVES_HEADER_LEN as usize];
    h[..8].copy_from_slice(LEAVES_MAGIC);
    h[8..12].copy_from_slice(&LEAVES_VERSION.to_le_bytes());
    h
}

/// What the log knows about one checkpoint without reading its file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointMeta {
    pub seq: u64,
    pub tree_size: u64,
    pub root: Digest,
}

/// A checkpoint file (`sth/<seq>.json`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredCheckpoint {
    /// The batch number: gap-free from 0.
    pub seq: u64,
    pub signed: SignedCheckpoint,
    /// The previous checkpoint's tree size (0 for the first).
    pub prev_tree_size: u64,
    /// The consistency proof from the previous tree to this one.
    pub consistency_from_prev: Vec<Digest>,
    /// Unix seconds when the batch was committed (informational: the
    /// witnesses' signed times are the ones that count).
    pub created_at: u64,
}

impl StoredCheckpoint {
    pub fn tree_size(&self) -> u64 {
        self.signed.checkpoint.tree_size
    }

    pub fn root(&self) -> Digest {
        self.signed.checkpoint.root
    }

    pub fn meta(&self) -> CheckpointMeta {
        CheckpointMeta {
            seq: self.seq,
            tree_size: self.tree_size(),
            root: self.root(),
        }
    }

    /// The file's JSON, also what `GET /v1/anchors/{seq}` starts from.
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("seq".into(), self.seq.into()),
            ("tree_size".into(), self.tree_size().into()),
            ("root".into(), hex_encode(&self.root()).into()),
            ("checkpoint".into(), self.signed.note.as_str().into()),
            (
                "anchor_digest".into(),
                hex_encode(&self.signed.anchor_digest).into(),
            ),
            ("prev_tree_size".into(), self.prev_tree_size.into()),
            (
                "consistency_from_prev".into(),
                hex_list(&self.consistency_from_prev),
            ),
            ("created_at".into(), self.created_at.into()),
        ])
    }

    /// Read a checkpoint file. The signed note must parse and agree with
    /// the size, root and digest fields beside it.
    pub fn from_json(doc: &Json) -> Result<StoredCheckpoint, AnchorError> {
        expect_keys(
            doc,
            &[
                "anchor_digest",
                "checkpoint",
                "consistency_from_prev",
                "created_at",
                "prev_tree_size",
                "root",
                "seq",
                "tree_size",
            ],
        )?;
        let signed = SignedCheckpoint::parse(json_str(doc, "checkpoint")?)?;
        let stored = StoredCheckpoint {
            seq: json_u64(doc, "seq")?,
            prev_tree_size: json_u64(doc, "prev_tree_size")?,
            consistency_from_prev: hex_list_from(doc, "consistency_from_prev")?,
            created_at: json_u64(doc, "created_at")?,
            signed,
        };
        let agrees = json_u64(doc, "tree_size")? == stored.tree_size()
            && json_hex::<32>(doc, "root")? == stored.root()
            && json_hex::<32>(doc, "anchor_digest")? == stored.signed.anchor_digest;
        if !agrees {
            return Err(AnchorError::Json(
                "checkpoint fields disagree with its signed note".into(),
            ));
        }
        Ok(stored)
    }
}

/// One leaf of a batch, as the batch index records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchLeaf {
    pub leaf_index: u64,
    pub leaf_type: LeafType,
    /// The plain id: the run id for a run (even when leaves carry HMAC
    /// ids), the access log's id for the access log.
    pub id: String,
}

/// The kind of an external witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WitnessKind {
    /// An RFC 3161 time-stamp authority.
    Rfc3161,
    /// A C2SP `tlog-witness` cosigner.
    Cosignature,
}

impl WitnessKind {
    /// The `type` value of the witness object in evidence (design 5.1).
    pub fn name(self) -> &'static str {
        match self {
            WitnessKind::Rfc3161 => "rfc3161",
            WitnessKind::Cosignature => "cosignature",
        }
    }

    pub fn from_name(name: &str) -> Option<WitnessKind> {
        match name {
            "rfc3161" => Some(WitnessKind::Rfc3161),
            "cosignature" => Some(WitnessKind::Cosignature),
            _ => None,
        }
    }
}

/// A verified witness result for one checkpoint
/// (`witness/<seq>/<label>.json`).
#[derive(Clone, Debug, PartialEq)]
pub struct WitnessRecord {
    pub seq: u64,
    /// A stable, file-name-safe label for the configured witness.
    pub label: String,
    pub kind: WitnessKind,
    /// The canonical operator (see [`crate::operator`]).
    pub operator: String,
    /// The witness's signed time: a token's genTime or a cosignature's
    /// timestamp, Unix seconds.
    pub time: u64,
    /// Unix seconds when the server verified and stored the result.
    pub recorded_at: u64,
    /// The witness object exactly as evidence carries it (design 5.1).
    pub object: Json,
}

impl WitnessRecord {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("seq".into(), self.seq.into()),
            ("witness".into(), self.label.as_str().into()),
            ("kind".into(), self.kind.name().into()),
            ("operator".into(), self.operator.as_str().into()),
            ("time".into(), self.time.into()),
            ("recorded_at".into(), self.recorded_at.into()),
            ("object".into(), self.object.clone()),
        ])
    }

    pub fn from_json(doc: &Json) -> Result<WitnessRecord, AnchorError> {
        expect_keys(
            doc,
            &[
                "kind",
                "object",
                "operator",
                "recorded_at",
                "seq",
                "time",
                "witness",
            ],
        )?;
        let kind = WitnessKind::from_name(json_str(doc, "kind")?)
            .ok_or_else(|| AnchorError::Json("unknown witness kind".into()))?;
        let object = doc.get("object").cloned().unwrap_or(Json::Null);
        if object.as_object().is_none() {
            return Err(AnchorError::Json("witness object is not an object".into()));
        }
        Ok(WitnessRecord {
            seq: json_u64(doc, "seq")?,
            label: json_str(doc, "witness")?.to_string(),
            kind,
            operator: json_str(doc, "operator")?.to_string(),
            time: json_u64(doc, "time")?,
            recorded_at: json_u64(doc, "recorded_at")?,
            object,
        })
    }
}

/// A leaf to append: its type, its plain id (run id), the id the leaf
/// carries (plain or HMAC, see [`crate::RunIdMode`]) and the journal state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewLeaf {
    pub leaf_type: LeafType,
    pub plain_id: String,
    pub leaf_id: Vec<u8>,
    pub entries: u64,
    pub head: Digest,
}

/// A leaf as committed in a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedLeaf {
    pub index: u64,
    pub leaf: Leaf,
    pub plain_id: String,
}

/// The result of [`AnchorLog::append_batch`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedBatch {
    pub checkpoint: StoredCheckpoint,
    pub leaves: Vec<CommittedLeaf>,
}

/// The newest leaf of one id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LatestLeaf {
    pub index: u64,
    pub entries: u64,
    pub head: Digest,
}

/// What [`AnchorLog::open`] found and did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Committed leaves.
    pub leaves: u64,
    /// Checkpoint files read.
    pub checkpoints: u64,
    /// The sequence number the next batch gets.
    pub next_seq: u64,
    /// Bytes past the last checkpointed leaf that were moved aside.
    pub uncommitted_bytes: u64,
    /// Where they went.
    pub moved_aside: Option<PathBuf>,
    /// Batch indexes newer than the latest checkpoint, and temporary files
    /// left by a crash, removed.
    pub removed_stale: Vec<PathBuf>,
    /// Sequence numbers below the latest with no checkpoint file. Appending
    /// stays safe, but the gap means files were deleted: alert.
    pub missing_seqs: Vec<u64>,
    /// Checkpoints whose batch index is missing (leaves cannot be mapped
    /// back to run ids for them).
    pub missing_batch_index: Vec<u64>,
}

/// The cumulative anchor log. See the module documentation.
///
/// Reads take `&self` and writes `&mut self`; callers share it behind a
/// lock (the [`Anchorer`](crate::Anchorer) uses an `RwLock`).
pub struct AnchorLog {
    dir: PathBuf,
    leaves: LeafFile,
    tree: TreeCache,
    checkpoints: Vec<CheckpointMeta>,
    latest: HashMap<Digest, LatestLeaf>,
    poisoned: bool,
}

impl std::fmt::Debug for AnchorLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchorLog")
            .field("dir", &self.dir)
            .field("leaves", &self.tree.size())
            .field("checkpoints", &self.checkpoints.len())
            .finish()
    }
}

impl AnchorLog {
    /// Open (or create) the anchor log in `dir` (`<data_dir>/anchors`) and
    /// recover it as the module documentation describes.
    pub fn open(dir: impl AsRef<Path>) -> Result<(AnchorLog, RecoveryReport), AnchorError> {
        AnchorLog::open_with_chunk_bits(dir, DEFAULT_CHUNK_BITS)
    }

    /// [`AnchorLog::open`] with a chosen tree chunk size (tests use small
    /// chunks to exercise chunk reads on small logs).
    pub fn open_with_chunk_bits(
        dir: impl AsRef<Path>,
        chunk_bits: u32,
    ) -> Result<(AnchorLog, RecoveryReport), AnchorError> {
        let dir = dir.as_ref().to_path_buf();
        prepare_layout(&dir)?;
        let mut report = RecoveryReport::default();
        let stored = load_checkpoints(&dir, &mut report)?;
        let next_seq = stored.last().map_or(0, |c| c.seq + 1);
        refuse_orphaned_witness_results(&dir, next_seq)?;
        let committed = stored.last().map_or(0, |c| c.tree_size());
        let boundaries = batch_boundaries(&stored);
        let checkpoints: Vec<CheckpointMeta> = stored.iter().map(StoredCheckpoint::meta).collect();

        let path = dir.join(LEAVES_FILE);
        if !path.exists() {
            if committed > 0 {
                return Err(AnchorError::Corrupt(format!(
                    "{} is missing but checkpoints cover {committed} leaves",
                    path.display()
                )));
            }
            write_atomic(&path, &leaves_header())?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(AnchorError::io(format!("opening {}", path.display())))?;
        let mut log = AnchorLog {
            leaves: LeafFile {
                path,
                file,
                len: LEAVES_HEADER_LEN,
                count: 0,
                chunk_offsets: Vec::new(),
                chunk_bits,
            },
            dir,
            tree: TreeCache::with_chunk_bits(chunk_bits),
            checkpoints,
            latest: HashMap::new(),
            poisoned: false,
        };
        log.scan_leaves(committed, &boundaries)?;
        // Every check has passed; only now is anything moved or removed.
        log.cut_uncommitted(&mut report)?;
        log.remove_stale(&mut report)?;
        for sub in ["", STH_DIR, BATCH_DIR] {
            report
                .removed_stale
                .extend(remove_temp_files(&log.dir.join(sub))?);
        }
        report.leaves = log.tree.size();
        report.checkpoints = log.checkpoints.len() as u64;
        report.next_seq = log.next_seq();
        Ok((log, report))
    }

    /// Close and open the log again, running recovery: the way out of a
    /// poisoned log (see the module documentation) without restarting the
    /// process. On error the log stays as it was (still poisoned).
    pub fn reopen(&mut self) -> Result<RecoveryReport, AnchorError> {
        let (fresh, report) = AnchorLog::open_with_chunk_bits(&self.dir, self.leaves.chunk_bits)?;
        *self = fresh;
        Ok(report)
    }

    /// True if an earlier write failed in a way that left memory and disk
    /// possibly out of step: writes are refused until [`AnchorLog::reopen`].
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Read the first `committed` leaves, rebuilding the tree, the chunk
    /// index and the latest-leaf map, and checking every checkpoint root,
    /// batch ordering and `prev_leaf_index` link on the way.
    fn scan_leaves(&mut self, committed: u64, boundaries: &[u64]) -> Result<(), AnchorError> {
        let ctx = format!("reading {}", self.leaves.path.display());
        // A second handle, so reading does not hold a borrow of the log
        // while the scan updates it.
        let file = self
            .leaves
            .file
            .try_clone()
            .map_err(AnchorError::io(&ctx))?;
        let mut reader = BufReader::with_capacity(1 << 20, file);
        reader
            .seek(SeekFrom::Start(0))
            .map_err(AnchorError::io(&ctx))?;
        let mut header = [0u8; LEAVES_HEADER_LEN as usize];
        reader
            .read_exact(&mut header)
            .map_err(|_| AnchorError::Corrupt("leaves file has no header".into()))?;
        if header != leaves_header() {
            return Err(AnchorError::Corrupt(
                "leaves file header is not PRAGLEAF version 1".into(),
            ));
        }
        let mut next_ckpt = 0usize;
        let mut next_boundary = 0usize;
        let mut prev_key: Option<(u8, Vec<u8>)> = None;
        let mut buf = Vec::with_capacity(MAX_LEAF_LEN);
        for index in 0..committed {
            let leaf = read_record(&mut reader, &mut buf).map_err(|why| {
                AnchorError::Corrupt(format!(
                    "leaf {index} of {committed} checkpointed leaves: {why}"
                ))
            })?;
            // Leaves of one batch are strictly ordered by (type, id).
            while next_boundary < boundaries.len() && boundaries[next_boundary] <= index {
                next_boundary += 1;
                prev_key = None;
            }
            let key = (leaf.leaf_type.byte(), leaf.id.clone());
            if prev_key.as_ref().is_some_and(|p| *p >= key) {
                return Err(AnchorError::Corrupt(format!(
                    "leaf {index} is out of order within its batch"
                )));
            }
            prev_key = Some(key);
            let expected_prev = self.latest_leaf(leaf.leaf_type, &leaf.id).map(|l| l.index);
            if leaf.prev_leaf_index != expected_prev {
                return Err(AnchorError::Corrupt(format!(
                    "leaf {index} names {:?} as its previous leaf, expected {expected_prev:?}",
                    leaf.prev_leaf_index
                )));
            }
            self.leaves.note_record(4 + buf.len() as u64);
            self.tree.push(merkle::leaf_hash(&buf));
            self.note_latest(index, &leaf);
            // Verify each checkpoint as soon as its tree is complete, while
            // the tail is in memory and the root costs no reads.
            while next_ckpt < self.checkpoints.len()
                && self.checkpoints[next_ckpt].tree_size == index + 1
            {
                let c = self.checkpoints[next_ckpt];
                if self.tree.root(index + 1, &NoSource)? != c.root {
                    return Err(AnchorError::Corrupt(format!(
                        "the leaves do not reproduce the root of checkpoint {}",
                        c.seq
                    )));
                }
                next_ckpt += 1;
            }
        }
        if let Some(c) = self.checkpoints.first() {
            if c.tree_size == 0 {
                return Err(AnchorError::Corrupt(format!(
                    "checkpoint {} has an empty tree",
                    c.seq
                )));
            }
        }
        Ok(())
    }

    /// Move bytes past the committed leaves aside and truncate.
    fn cut_uncommitted(&mut self, report: &mut RecoveryReport) -> Result<(), AnchorError> {
        let ctx = format!("recovering {}", self.leaves.path.display());
        let file_len = self
            .leaves
            .file
            .metadata()
            .map_err(AnchorError::io(&ctx))?
            .len();
        let valid = self.leaves.len;
        if file_len <= valid {
            return Ok(());
        }
        let mut tail = vec![0u8; (file_len - valid) as usize];
        read_exact_at(&self.leaves.file, &mut tail, valid).map_err(AnchorError::io(&ctx))?;
        let aside = self
            .dir
            .join(format!("{LEAVES_FILE}.uncommitted-{}", unix_millis()));
        create_new_durable(&aside, &tail)?;
        self.leaves
            .file
            .set_len(valid)
            .and_then(|_| self.leaves.file.sync_all())
            .map_err(AnchorError::io(&ctx))?;
        report.uncommitted_bytes = tail.len() as u64;
        report.moved_aside = Some(aside);
        Ok(())
    }

    /// Remove batch indexes newer than the latest checkpoint (written
    /// before a crash stopped the checkpoint), and note the batch indexes
    /// that are missing. Witness results are never removed: one past the
    /// latest checkpoint was refused as corruption before this runs.
    fn remove_stale(&mut self, report: &mut RecoveryReport) -> Result<(), AnchorError> {
        let next = self.next_seq();
        let batch_dir = self.dir.join(BATCH_DIR);
        let mut present = Vec::new();
        for (seq, path) in list_seq_entries(&batch_dir, ".json")? {
            if seq >= next {
                fs::remove_file(&path)
                    .map_err(AnchorError::io(format!("removing {}", path.display())))?;
                report.removed_stale.push(path);
            } else {
                present.push(seq);
            }
        }
        sync_dir(&batch_dir)?;
        present.sort_unstable();
        for c in &self.checkpoints {
            if present.binary_search(&c.seq).is_err() {
                report.missing_batch_index.push(c.seq);
            }
        }
        Ok(())
    }

    fn note_latest(&mut self, index: u64, leaf: &Leaf) {
        self.latest.insert(
            id_key(leaf.leaf_type, &leaf.id),
            LatestLeaf {
                index,
                entries: leaf.entries,
                head: leaf.head,
            },
        );
    }

    // -----------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------

    /// The anchors directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Committed leaves.
    pub fn size(&self) -> u64 {
        self.tree.size()
    }

    /// The sequence number the next batch gets: the latest plus one.
    pub fn next_seq(&self) -> u64 {
        self.checkpoints.last().map_or(0, |c| c.seq + 1)
    }

    /// Every checkpoint, by sequence number.
    pub fn checkpoints(&self) -> &[CheckpointMeta] {
        &self.checkpoints
    }

    /// The latest checkpoint.
    pub fn latest_checkpoint(&self) -> Option<CheckpointMeta> {
        self.checkpoints.last().copied()
    }

    /// The checkpoint with sequence number `seq`.
    pub fn checkpoint_meta(&self, seq: u64) -> Option<CheckpointMeta> {
        self.checkpoints
            .binary_search_by_key(&seq, |c| c.seq)
            .ok()
            .map(|i| self.checkpoints[i])
    }

    /// The checkpoint of the batch that appended leaf `index`: the first
    /// whose tree contains it.
    pub fn checkpoint_for_leaf(&self, index: u64) -> Option<CheckpointMeta> {
        let i = self.checkpoints.partition_point(|c| c.tree_size <= index);
        self.checkpoints.get(i).copied()
    }

    /// Read checkpoint file `seq`.
    pub fn checkpoint(&self, seq: u64) -> Result<StoredCheckpoint, AnchorError> {
        let path = self.dir.join(STH_DIR).join(seq_name(seq, ".json"));
        let doc = read_json(&path)?;
        let stored = StoredCheckpoint::from_json(&doc)?;
        if stored.seq != seq {
            return Err(AnchorError::Corrupt(format!(
                "{} holds checkpoint {}",
                path.display(),
                stored.seq
            )));
        }
        Ok(stored)
    }

    /// The newest leaf of `(leaf_type, leaf_id)`.
    pub fn latest_leaf(&self, leaf_type: LeafType, leaf_id: &[u8]) -> Option<LatestLeaf> {
        self.latest.get(&id_key(leaf_type, leaf_id)).copied()
    }

    /// The number of distinct ids with at least one leaf.
    pub fn ids(&self) -> usize {
        self.latest.len()
    }

    /// The tree root after the first `size` leaves.
    pub fn root(&self, size: u64) -> Result<Digest, AnchorError> {
        self.tree.root(size, &self.leaves)
    }

    /// The inclusion proof of leaf `index` in the tree of `tree_size`.
    pub fn inclusion_proof(&self, index: u64, tree_size: u64) -> Result<Vec<Digest>, AnchorError> {
        self.tree.inclusion_proof(index, tree_size, &self.leaves)
    }

    /// The consistency proof from the tree of `old` leaves to that of
    /// `new` leaves.
    pub fn consistency_proof(&self, old: u64, new: u64) -> Result<Vec<Digest>, AnchorError> {
        self.tree.consistency_proof(old, new, &self.leaves)
    }

    /// Leaf `index`.
    pub fn read_leaf(&self, index: u64) -> Result<Leaf, AnchorError> {
        Ok(self.read_leaves(index, index + 1)?.pop().expect("one leaf"))
    }

    /// Leaves `from..to` (for `GET /v1/anchors/log` and for mapping a
    /// batch's leaves).
    pub fn read_leaves(&self, from: u64, to: u64) -> Result<Vec<Leaf>, AnchorError> {
        if from > to || to > self.size() {
            return Err(AnchorError::OutOfRange(format!(
                "leaves {from}..{to} of a log of {}",
                self.size()
            )));
        }
        let bits = self.leaves.chunk_bits;
        let mut out = Vec::with_capacity((to - from) as usize);
        let mut chunk = from >> bits;
        while out.len() < (to - from) as usize {
            let records = self.leaves.chunk_records(chunk)?;
            let base = chunk << bits;
            for (i, data) in records.iter().enumerate() {
                let index = base + i as u64;
                if index >= from && index < to {
                    out.push(Leaf::decode(data)?);
                }
            }
            chunk += 1;
        }
        Ok(out)
    }

    /// Every leaf of `(leaf_type, leaf_id)`, oldest first, following
    /// `prev_leaf_index` back from the newest.
    pub fn leaf_chain(
        &self,
        leaf_type: LeafType,
        leaf_id: &[u8],
    ) -> Result<Vec<(u64, Leaf)>, AnchorError> {
        let mut chain = Vec::new();
        let mut next = self.latest_leaf(leaf_type, leaf_id).map(|l| l.index);
        while let Some(index) = next {
            let leaf = self.read_leaf(index)?;
            if leaf.leaf_type != leaf_type || leaf.id != leaf_id {
                return Err(AnchorError::Corrupt(format!(
                    "leaf {index} belongs to another id"
                )));
            }
            next = leaf.prev_leaf_index;
            if next.is_some_and(|p| p >= index) {
                return Err(AnchorError::Corrupt(format!("leaf {index} links forward")));
            }
            chain.push((index, leaf));
        }
        chain.reverse();
        Ok(chain)
    }

    /// The batch index of checkpoint `seq`: which plain id each of its
    /// leaves belongs to.
    pub fn batch_index(&self, seq: u64) -> Result<Vec<BatchLeaf>, AnchorError> {
        let path = self.dir.join(BATCH_DIR).join(seq_name(seq, ".json"));
        let doc = read_json(&path)?;
        parse_batch_index(&doc, seq)
    }

    /// The verified witness results stored for checkpoint `seq`. Files that
    /// do not parse (damaged: results are published atomically) are
    /// skipped: they count for nothing, and [`AnchorLog::store_witness`]
    /// replaces them with the next verified result.
    pub fn witnesses(&self, seq: u64) -> Result<Vec<WitnessRecord>, AnchorError> {
        let dir = self.dir.join(WITNESS_DIR).join(seq_name(seq, ""));
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AnchorError::io(format!("listing {}", dir.display()))(e)),
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        paths.sort();
        let mut out = Vec::new();
        for path in paths {
            if let Ok(record) = read_json(&path).and_then(|d| WitnessRecord::from_json(&d)) {
                if record.seq == seq {
                    out.push(record);
                }
            }
        }
        Ok(out)
    }

    // -----------------------------------------------------------------
    // Writes
    // -----------------------------------------------------------------

    /// Append one batch: order the leaves by (type, id), reject duplicate
    /// ids, link each to its id's previous leaf, write and fsync them,
    /// write the batch index, sign the checkpoint and publish it. Nothing
    /// is committed unless every step succeeds. A failure before the
    /// checkpoint file exists rolls the leaves back; a failure after it may
    /// exist (its directory fsync) poisons the log instead, as the module
    /// documentation explains.
    pub fn append_batch(
        &mut self,
        mut new_leaves: Vec<NewLeaf>,
        signer: &LogSigner,
        now_unix: u64,
    ) -> Result<CommittedBatch, AnchorError> {
        if self.poisoned {
            return Err(AnchorError::Poisoned);
        }
        if new_leaves.is_empty() {
            return Err(AnchorError::EmptyBatch);
        }
        for l in &new_leaves {
            if l.leaf_id.is_empty() || l.leaf_id.len() > MAX_ID_LEN || l.plain_id.is_empty() {
                return Err(AnchorError::InvalidLeaf(format!(
                    "id of {} bytes for {:?}",
                    l.leaf_id.len(),
                    l.plain_id
                )));
            }
        }
        new_leaves.sort_by(|a, b| {
            (a.leaf_type.byte(), &a.leaf_id).cmp(&(b.leaf_type.byte(), &b.leaf_id))
        });
        if let Some(w) = new_leaves
            .windows(2)
            .find(|w| (w[0].leaf_type, &w[0].leaf_id) == (w[1].leaf_type, &w[1].leaf_id))
        {
            return Err(AnchorError::DuplicateId {
                leaf_type: w[0].leaf_type.byte(),
                id_hex: hex_encode(&w[0].leaf_id),
            });
        }

        let seq = self.next_seq();
        let old_size = self.size();
        let old_len = self.leaves.len;
        let committed: Vec<CommittedLeaf> = new_leaves
            .into_iter()
            .enumerate()
            .map(|(i, l)| CommittedLeaf {
                index: old_size + i as u64,
                leaf: Leaf {
                    prev_leaf_index: self.latest_leaf(l.leaf_type, &l.leaf_id).map(|p| p.index),
                    leaf_type: l.leaf_type,
                    id: l.leaf_id,
                    entries: l.entries,
                    head: l.head,
                },
                plain_id: l.plain_id,
            })
            .collect();
        let encoded: Vec<Vec<u8>> = committed.iter().map(|c| c.leaf.encode()).collect();
        self.leaves
            .append(&encoded)
            .map_err(|e| self.fail_append(e))?;
        for data in &encoded {
            self.tree.push(merkle::leaf_hash(data));
        }

        match self.commit_checkpoint(seq, old_size, &committed, signer, now_unix) {
            Ok(checkpoint) => {
                for c in &committed {
                    self.note_latest(c.index, &c.leaf);
                }
                self.checkpoints.push(checkpoint.meta());
                Ok(CommittedBatch {
                    checkpoint,
                    leaves: committed,
                })
            }
            Err(CommitError {
                error,
                published: false,
            }) => {
                self.rollback(old_size, old_len);
                Err(error)
            }
            Err(CommitError {
                error,
                published: true,
            }) => {
                // The checkpoint file exists and may survive a crash, so the
                // leaves under it must stay; reopening settles it.
                self.poisoned = true;
                Err(error)
            }
        }
    }

    /// Sign and publish the checkpoint for the leaves just appended, with
    /// the batch index first. On failure the error says whether the
    /// checkpoint file may exist: if not, nothing of this batch remains on
    /// disk except the leaves, which the caller rolls back.
    fn commit_checkpoint(
        &mut self,
        seq: u64,
        old_size: u64,
        committed: &[CommittedLeaf],
        signer: &LogSigner,
        now_unix: u64,
    ) -> Result<StoredCheckpoint, CommitError> {
        let size = self.size();
        let root = self.tree.root(size, &NoSource)?;
        let prev_tree_size = self.checkpoints.last().map_or(0, |c| c.tree_size);
        debug_assert_eq!(prev_tree_size, old_size);
        let stored = StoredCheckpoint {
            seq,
            signed: signer.sign_checkpoint(size, root)?,
            prev_tree_size,
            consistency_from_prev: self.tree.consistency_proof(
                prev_tree_size,
                size,
                &self.leaves,
            )?,
            created_at: now_unix,
        };
        // The batch index is replaced, not published: one left by an
        // earlier failed attempt at this sequence number is stale by
        // definition and must not block the retry.
        let batch_path = self.dir.join(BATCH_DIR).join(seq_name(seq, ".json"));
        let batch = batch_index_json(seq, old_size, committed);
        write_atomic(&batch_path, json_file_bytes(&batch).as_slice())?;
        let sth_path = self.dir.join(STH_DIR).join(seq_name(seq, ".json"));
        publish_new_durable(&sth_path, &json_file_bytes(&stored.to_json())).map_err(|e| {
            if !e.published {
                let _ = fs::remove_file(&batch_path);
            }
            CommitError {
                error: e.error,
                published: e.published,
            }
        })?;
        Ok(stored)
    }

    /// Undo a batch's leaves after a failed commit. If even that fails the
    /// log is poisoned and refuses writes until reopened.
    fn rollback(&mut self, old_size: u64, old_len: u64) {
        let tree_ok = self.tree.truncate(old_size, &self.leaves).is_ok();
        let file_ok = self.leaves.truncate(old_len, old_size).is_ok();
        if !(tree_ok && file_ok) {
            self.poisoned = true;
        }
    }

    /// Map an append error, poisoning the log if the file could not be
    /// restored.
    fn fail_append(&mut self, e: AppendError) -> AnchorError {
        if e.poisoned {
            self.poisoned = true;
        }
        AnchorError::io(format!("appending to {}", self.leaves.path.display()))(e.source)
    }

    /// Store a verified witness result for checkpoint `record.seq`. Returns
    /// false if a valid result for this witness was already stored (the
    /// first one wins; the file is never overwritten).
    pub fn store_witness(&mut self, record: &WitnessRecord) -> Result<bool, AnchorError> {
        if self.poisoned {
            return Err(AnchorError::Poisoned);
        }
        if self.checkpoint_meta(record.seq).is_none() {
            return Err(AnchorError::OutOfRange(format!(
                "no checkpoint {}",
                record.seq
            )));
        }
        if !is_safe_label(&record.label) {
            return Err(AnchorError::Json(format!(
                "witness label {:?} is not [a-z0-9._-]{{1,64}}",
                record.label
            )));
        }
        let dir = self.dir.join(WITNESS_DIR).join(seq_name(record.seq, ""));
        ensure_dir(&dir)?;
        let path = dir.join(format!("{}.json", record.label));
        let bytes = json_file_bytes(&record.to_json());
        match publish_new_durable(&path, &bytes).map_err(AnchorError::from) {
            Ok(()) => Ok(true),
            Err(AnchorError::Io { source, .. })
                if source.kind() == io::ErrorKind::AlreadyExists =>
            {
                // A valid earlier result stands. One that does not parse
                // (damaged, or written before results were published
                // atomically) counts for nothing and is replaced by this
                // verified one.
                let valid = read_json(&path)
                    .and_then(|d| WitnessRecord::from_json(&d))
                    .is_ok();
                if valid {
                    Ok(false)
                } else {
                    write_atomic(&path, &bytes)?;
                    Ok(true)
                }
            }
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------
// The leaves file
// ---------------------------------------------------------------------

/// `log.leaves` with an index of where each chunk of leaves starts, so a
/// proof reads one chunk instead of scanning.
struct LeafFile {
    path: PathBuf,
    file: File,
    /// Bytes of header plus committed records.
    len: u64,
    count: u64,
    /// Byte offset of the first record of each chunk.
    chunk_offsets: Vec<u64>,
    chunk_bits: u32,
}

/// A failed append, and whether the file could be restored.
struct AppendError {
    source: io::Error,
    poisoned: bool,
}

/// A failed checkpoint commit, and whether the checkpoint file may exist
/// (in which case the leaves under it must not be rolled back).
struct CommitError {
    error: AnchorError,
    published: bool,
}

impl From<AnchorError> for CommitError {
    fn from(error: AnchorError) -> CommitError {
        CommitError {
            error,
            published: false,
        }
    }
}

impl LeafFile {
    /// Account for one record of `bytes` (length prefix included) at the
    /// current end.
    fn note_record(&mut self, bytes: u64) {
        if self.count & ((1 << self.chunk_bits) - 1) == 0 {
            self.chunk_offsets.push(self.len);
        }
        self.count += 1;
        self.len += bytes;
    }

    /// Append records with one write and one fsync. On failure the file is
    /// cut back to its old length.
    fn append(&mut self, records: &[Vec<u8>]) -> Result<(), AppendError> {
        let mut buf = Vec::with_capacity(records.iter().map(|r| r.len() + 4).sum());
        for r in records {
            buf.extend_from_slice(&(r.len() as u32).to_le_bytes());
            buf.extend_from_slice(r);
        }
        let result = (|| -> io::Result<()> {
            // Someone else writing the file would corrupt the log; refuse.
            let actual = self.file.metadata()?.len();
            if actual != self.len {
                return Err(io::Error::other(format!(
                    "leaves file is {actual} bytes, expected {}",
                    self.len
                )));
            }
            (&self.file).seek(SeekFrom::Start(self.len))?;
            (&self.file).write_all(&buf)?;
            self.file.sync_data()
        })();
        if let Err(source) = result {
            let restored = self
                .file
                .set_len(self.len)
                .and_then(|_| self.file.sync_all())
                .is_ok();
            return Err(AppendError {
                source,
                poisoned: !restored,
            });
        }
        for r in records {
            self.note_record(4 + r.len() as u64);
        }
        Ok(())
    }

    /// Cut the file back to `len` bytes holding `count` records.
    fn truncate(&mut self, len: u64, count: u64) -> io::Result<()> {
        self.file.set_len(len)?;
        self.file.sync_all()?;
        self.len = len;
        self.count = count;
        let chunks = count.div_ceil(1 << self.chunk_bits);
        self.chunk_offsets.truncate(chunks as usize);
        Ok(())
    }

    /// The raw leaf data of every record in `chunk`.
    fn chunk_records(&self, chunk: u64) -> Result<Vec<Vec<u8>>, AnchorError> {
        let ctx = || format!("reading {}", self.path.display());
        let start = *self
            .chunk_offsets
            .get(chunk as usize)
            .ok_or_else(|| AnchorError::OutOfRange(format!("leaf chunk {chunk}")))?;
        let end = self
            .chunk_offsets
            .get(chunk as usize + 1)
            .copied()
            .unwrap_or(self.len);
        let mut bytes = vec![0u8; (end - start) as usize];
        read_exact_at(&self.file, &mut bytes, start).map_err(AnchorError::io(ctx()))?;
        let mut records = Vec::with_capacity(1 << self.chunk_bits);
        let mut rest = &bytes[..];
        while !rest.is_empty() {
            if rest.len() < 4 {
                return Err(AnchorError::Corrupt(format!(
                    "chunk {chunk} ends mid-record"
                )));
            }
            let len = u32::from_le_bytes(rest[..4].try_into().expect("4 bytes")) as usize;
            if len > MAX_LEAF_LEN || rest.len() < 4 + len {
                return Err(AnchorError::Corrupt(format!(
                    "chunk {chunk} ends mid-record"
                )));
            }
            records.push(rest[4..4 + len].to_vec());
            rest = &rest[4 + len..];
        }
        Ok(records)
    }
}

impl LeafHashSource for LeafFile {
    fn chunk_leaf_hashes(&self, chunk: u64, chunk_bits: u32) -> io::Result<Vec<Digest>> {
        debug_assert_eq!(chunk_bits, self.chunk_bits);
        let records = self
            .chunk_records(chunk)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(records.iter().map(|r| merkle::leaf_hash(r)).collect())
    }
}

/// Read one `u32 LE len ‖ leaf_data` record into `buf` and decode it.
fn read_record(reader: &mut impl Read, buf: &mut Vec<u8>) -> Result<Leaf, String> {
    let mut len = [0u8; 4];
    reader
        .read_exact(&mut len)
        .map_err(|e| format!("length unreadable ({e})"))?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_LEAF_LEN {
        return Err(format!("record length {len} exceeds {MAX_LEAF_LEN}"));
    }
    buf.resize(len, 0);
    reader
        .read_exact(buf)
        .map_err(|e| format!("record unreadable ({e})"))?;
    Leaf::decode(buf).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------
// Checkpoint and batch files
// ---------------------------------------------------------------------

/// Load every checkpoint file in sequence order. Checkpoint files are
/// published atomically, so a crash never leaves a torn one: any file that
/// does not parse, the latest included, is corruption.
fn load_checkpoints(
    dir: &Path,
    report: &mut RecoveryReport,
) -> Result<Vec<StoredCheckpoint>, AnchorError> {
    let sth = dir.join(STH_DIR);
    let mut files = list_seq_entries(&sth, ".json")?;
    files.sort_by_key(|(seq, _)| *seq);
    let mut out: Vec<StoredCheckpoint> = Vec::with_capacity(files.len());
    for (seq, path) in &files {
        let bytes =
            fs::read(path).map_err(AnchorError::io(format!("reading {}", path.display())))?;
        let doc = Json::parse_bytes(&bytes).map_err(|e| {
            AnchorError::Corrupt(format!(
                "{} is not JSON ({e}); checkpoint files are published whole, so it was \
                 damaged after it was written: restore it from a backup",
                path.display()
            ))
        })?;
        let stored = StoredCheckpoint::from_json(&doc)
            .map_err(|e| AnchorError::Corrupt(format!("{}: {e}", path.display())))?;
        if stored.seq != *seq {
            return Err(AnchorError::Corrupt(format!(
                "{} holds checkpoint {}",
                path.display(),
                stored.seq
            )));
        }
        if let Some(prev) = out.last() {
            if stored.tree_size() <= prev.tree_size() {
                return Err(AnchorError::Corrupt(format!(
                    "checkpoint {} does not grow the tree past checkpoint {}",
                    stored.seq, prev.seq
                )));
            }
            report.missing_seqs.extend(prev.seq + 1..stored.seq);
        } else {
            report.missing_seqs.extend(0..stored.seq);
        }
        out.push(stored);
    }
    Ok(out)
}

/// Create the anchors directory and its subdirectories if missing, and
/// fsync each one. Whatever recovery reads must be durable before anything
/// is built on it: a checkpoint whose directory entry a failed fsync left
/// only in the page cache is made durable here, or the open fails.
fn prepare_layout(dir: &Path) -> Result<(), AnchorError> {
    for sub in ["", STH_DIR, BATCH_DIR, WITNESS_DIR] {
        ensure_dir(&dir.join(sub))?;
        sync_dir(&dir.join(sub))?;
    }
    Ok(())
}

/// Refuse to recover past a checkpoint that witnesses have seen. Witness
/// results are stored only for a checkpoint already durable, so results
/// for `next_seq` or later mean its checkpoint file was committed and has
/// since been lost or deleted. Treating its leaves as uncommitted would
/// sign another tree under the same sequence number, a checkpoint
/// inconsistent with one already signed and shown to third parties (C2SP
/// `tlog-checkpoint` forbids that), and would throw their evidence away.
fn refuse_orphaned_witness_results(dir: &Path, next_seq: u64) -> Result<(), AnchorError> {
    let witness_dir = dir.join(WITNESS_DIR);
    let mut orphaned: Vec<u64> = list_seq_entries(&witness_dir, "")?
        .into_iter()
        .map(|(seq, _)| seq)
        .filter(|seq| *seq >= next_seq)
        .collect();
    orphaned.sort_unstable();
    match orphaned.first() {
        None => Ok(()),
        Some(seq) => Err(AnchorError::Corrupt(format!(
            "witness results exist for checkpoint {seq} but its checkpoint file is missing \
             (the latest is {}): it was committed and witnessed, so recovering past it would \
             sign a different tree under the same sequence number; restore {} from a backup",
            next_seq
                .checked_sub(1)
                .map_or_else(|| "none".to_string(), |s| s.to_string()),
            Path::new(STH_DIR).join(seq_name(*seq, ".json")).display()
        ))),
    }
}

/// The leaf indexes where batches start: every checkpoint's previous and
/// own tree size, so ordering is checked per batch even across a missing
/// checkpoint file.
fn batch_boundaries(stored: &[StoredCheckpoint]) -> Vec<u64> {
    let mut b: Vec<u64> = stored
        .iter()
        .flat_map(|c| [c.prev_tree_size, c.tree_size()])
        .collect();
    b.sort_unstable();
    b.dedup();
    b
}

fn batch_index_json(seq: u64, first_leaf: u64, leaves: &[CommittedLeaf]) -> Json {
    let items = leaves
        .iter()
        .map(|c| {
            Json::Object(vec![
                ("type".into(), c.leaf.leaf_type.name().into()),
                ("id".into(), c.plain_id.as_str().into()),
            ])
        })
        .collect::<Vec<Json>>();
    Json::Object(vec![
        ("seq".into(), seq.into()),
        ("first_leaf".into(), first_leaf.into()),
        ("leaves".into(), Json::Array(items)),
    ])
}

fn parse_batch_index(doc: &Json, seq: u64) -> Result<Vec<BatchLeaf>, AnchorError> {
    expect_keys(doc, &["first_leaf", "leaves", "seq"])?;
    if json_u64(doc, "seq")? != seq {
        return Err(AnchorError::Json(format!("batch index is not for {seq}")));
    }
    let first = json_u64(doc, "first_leaf")?;
    let items = doc
        .get("leaves")
        .and_then(Json::as_array)
        .ok_or_else(|| AnchorError::Json("leaves is not an array".into()))?;
    items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            expect_keys(item, &["id", "type"])?;
            let leaf_type = LeafType::from_name(json_str(item, "type")?)
                .ok_or_else(|| AnchorError::Json("unknown leaf type".into()))?;
            Ok(BatchLeaf {
                leaf_index: first + i as u64,
                leaf_type,
                id: json_str(item, "id")?.to_string(),
            })
        })
        .collect()
}

/// Entries of `dir` named `<20 digits><ext>`, with their numbers.
fn list_seq_entries(dir: &Path, ext: &str) -> Result<Vec<(u64, PathBuf)>, AnchorError> {
    let entries =
        fs::read_dir(dir).map_err(AnchorError::io(format!("listing {}", dir.display())))?;
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(AnchorError::io(format!("listing {}", dir.display())))?;
        let name = entry.file_name();
        if let Some(seq) = name.to_str().and_then(|n| parse_seq_name(n, ext)) {
            out.push((seq, entry.path()));
        }
    }
    Ok(out)
}

fn read_json(path: &Path) -> Result<Json, AnchorError> {
    let bytes = fs::read(path).map_err(AnchorError::io(format!("reading {}", path.display())))?;
    Json::parse_bytes(&bytes).map_err(|e| AnchorError::Json(format!("{}: {e}", path.display())))
}

/// A JSON document as file bytes: compact, with a final newline.
fn json_file_bytes(doc: &Json) -> Vec<u8> {
    let mut s = doc.to_string();
    s.push('\n');
    s.into_bytes()
}

/// Refuse documents with missing or unknown keys (strict JSON, design
/// 3.7).
pub(crate) fn expect_keys(doc: &Json, keys: &[&str]) -> Result<(), AnchorError> {
    let members = doc
        .as_object()
        .ok_or_else(|| AnchorError::Json("expected an object".into()))?;
    let ok = members.len() == keys.len() && members.iter().all(|(k, _)| keys.contains(&k.as_str()));
    if ok {
        Ok(())
    } else {
        Err(AnchorError::Json(format!(
            "expected exactly the keys {keys:?}"
        )))
    }
}

pub(crate) fn hex_list(digests: &[Digest]) -> Json {
    Json::Array(digests.iter().map(|d| hex_encode(d).into()).collect())
}

fn hex_list_from(doc: &Json, key: &str) -> Result<Vec<Digest>, AnchorError> {
    let items = doc
        .get(key)
        .and_then(Json::as_array)
        .ok_or_else(|| AnchorError::Json(format!("{key} is not an array")))?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .and_then(|s| pragmatic::encoding::hex_decode_exact::<32>(s).ok())
                .ok_or_else(|| AnchorError::Json(format!("{key} holds a non-digest")))
        })
        .collect()
}

/// A witness label usable as a file name on every platform.
fn is_safe_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 64
        && !label.starts_with('.')
        && label.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

#[cfg(test)]
mod tests;
