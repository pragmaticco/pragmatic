//! # pragmatic-anchor: anchoring for Stet Server
//!
//! Stet Server keeps every run's journal tamper-evident on its own; an
//! *anchor* makes it tamper-evident against the server's operator too. This
//! crate is the anchoring library the server calls (design sections 4.7 and
//! 4.8):
//!
//! - [`AnchorLog`]: one cumulative, append-only RFC 6962 Merkle log of
//!   [`Leaf`]s, each committing to a journal's `(entries, head)` and
//!   linked to the same journal's previous leaf; stored as
//!   `anchors/log.leaves` plus one checkpoint file per batch, recovered at
//!   startup, with O(log n) proofs over millions of leaves ([`tree`]).
//! - [`LogSigner`]: checkpoints in the C2SP `tlog-checkpoint` format,
//!   signed as C2SP signed notes with the server's Ed25519 key, plus key
//!   rotation records ([`checkpoint`]).
//! - [`tsa`]: an RFC 3161 client (spacing, timeouts, retries with fresh
//!   nonces), response validation through the core's `tsp` module, and CMS
//!   verification with `openssl ts -verify` against pinned roots.
//! - [`operator`]: operator grouping and the independence policy that
//!   decides when a checkpoint counts as independently anchored.
//! - [`witness`]: a C2SP `tlog-witness` client, and the witness-mode
//!   service a server runs to cosign other logs' checkpoints.
//! - [`Anchorer`]: one batch end to end (snapshots, leaves, checkpoint,
//!   witnesses, storage, retries), reporting which runs advanced their
//!   independently anchored length.
//! - [`evidence`]: a run's anchor section for an evidence bundle (design
//!   5.1).
//! - [`lag`] and [`schedule`]: inputs for the anchoring lag metric and
//!   batch timing.
//!
//! All formats (leaf hashes, proofs, checkpoints, notes, cosignatures,
//! time-stamp requests and tokens, strict JSON) come from the core
//! `pragmatic` crate, so the server that writes them and the CLI and
//! verifiers that read them cannot drift apart.
//!
//! # License
//!
//! This crate is part of Stet's commercial layer. Its source is public
//! under the Business Source License 1.1 (see `LICENSE` in this directory):
//! non-production use is free; production use needs a commercial license
//! from Pragmatic Research, Inc. Each version becomes Apache-2.0 four years
//! after its release.

pub mod anchorer;
pub mod checkpoint;
pub mod error;
pub mod evidence;
mod fsutil;
pub mod journal_file;
pub mod lag;
pub mod leaf;
pub mod log;
pub mod operator;
pub mod schedule;
pub mod tree;
pub mod tsa;
pub mod witness;

pub use anchorer::{
    Advanced, AnchorStatus, AnchoredLeaf, Anchorer, AnchorerConfig, BatchOutcome, ExternalWitness,
    RetryPolicy, SkipReason, SkippedRun, Snapshot, SnapshotProvider, WitnessAttempt,
};
pub use checkpoint::{
    anchor_digest, origin_for, KeyInfo, KeyRotation, LogSigner, SignedCheckpoint,
};
pub use error::AnchorError;
pub use evidence::{AnchorSection, EvidenceAnchor};
pub use lag::LagTracker;
pub use leaf::{Leaf, LeafType, RunIdMode, ACCESS_LOG_ID, WITNESS_RUN_ID};
pub use log::{
    AnchorLog, CheckpointMeta, RecoveryReport, StoredCheckpoint, WitnessKind, WitnessRecord,
};
pub use operator::{canonical_operator, IndependencePolicy};
pub use schedule::BatchSchedule;
pub use tree::TreeCache;
pub use witness::{
    Cosigner, Refused, RejectRecord, Submission, WitnessConfig, WitnessCore, WitnessOrigin,
};
