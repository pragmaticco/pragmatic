//! The error type shared by the anchor log, the checkpoint signer and the
//! [`Anchorer`](crate::Anchorer).
//!
//! Network-facing parts have their own error types ([`TsaError`],
//! [`WitnessClientError`], [`AddCheckpointError`]) because their callers
//! act on the details (retry, back off, answer with an HTTP status); the
//! errors here are about local state, and the caller's only decisions are
//! whether to alert and whether the anchor log can still be written.
//!
//! [`TsaError`]: crate::tsa::TsaError
//! [`WitnessClientError`]: crate::witness::WitnessClientError
//! [`AddCheckpointError`]: crate::witness::AddCheckpointError

use std::fmt;
use std::io;

use pragmatic::note::NoteError;

/// Why an anchoring operation failed.
#[non_exhaustive]
#[derive(Debug)]
pub enum AnchorError {
    /// A file system operation failed. `context` names the operation and
    /// the path.
    Io { context: String, source: io::Error },
    /// The anchor log on disk is damaged or inconsistent: a leaf that does
    /// not decode inside the checkpointed prefix, a checkpoint whose root
    /// the leaves do not reproduce, a broken `prev_leaf_index` chain. This
    /// is never repaired automatically; an operator must look.
    Corrupt(String),
    /// A leaf or a request to build one is malformed (an empty or
    /// over-long id, an unknown type byte, a short encoding).
    InvalidLeaf(String),
    /// Two snapshots in one batch named the same `(type, id)`. The whole
    /// batch is aborted (design 4.7), because one of them is wrong and
    /// anchoring either would put a false claim under a signature.
    DuplicateId { leaf_type: u8, id_hex: String },
    /// A batch with no leaves was submitted; batches run only when new
    /// leaves exist.
    EmptyBatch,
    /// A leaf index, tree size or sequence number outside what the log
    /// holds.
    OutOfRange(String),
    /// A signing key could not be read, parsed or used.
    Key(String),
    /// A checkpoint or signed note could not be built or parsed.
    Note(NoteError),
    /// A stored JSON document is not what this crate writes.
    Json(String),
    /// The [`SnapshotProvider`](crate::SnapshotProvider) failed, so no
    /// batch was attempted.
    Provider(String),
    /// An earlier write failed and could not be rolled back, so the files
    /// on disk may no longer match memory. The log must be reopened, which
    /// runs recovery.
    Poisoned,
}

impl AnchorError {
    /// An [`AnchorError::Io`] with context, for `map_err`.
    pub(crate) fn io(context: impl Into<String>) -> impl FnOnce(io::Error) -> AnchorError {
        let context = context.into();
        move |source| AnchorError::Io { context, source }
    }
}

impl fmt::Display for AnchorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnchorError::Io { context, source } => write!(f, "{context}: {source}"),
            AnchorError::Corrupt(why) => write!(f, "anchor log is corrupt: {why}"),
            AnchorError::InvalidLeaf(why) => write!(f, "invalid anchor leaf: {why}"),
            AnchorError::DuplicateId { leaf_type, id_hex } => write!(
                f,
                "batch aborted: id {id_hex} (type {leaf_type}) appears twice"
            ),
            AnchorError::EmptyBatch => f.write_str("a batch needs at least one leaf"),
            AnchorError::OutOfRange(why) => write!(f, "out of range: {why}"),
            AnchorError::Key(why) => write!(f, "signing key: {why}"),
            AnchorError::Note(e) => write!(f, "checkpoint: {e}"),
            AnchorError::Json(why) => write!(f, "anchor log JSON: {why}"),
            AnchorError::Provider(why) => write!(f, "snapshot provider failed: {why}"),
            AnchorError::Poisoned => {
                f.write_str("an earlier anchor log write could not be rolled back; reopen the log")
            }
        }
    }
}

impl std::error::Error for AnchorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AnchorError::Io { source, .. } => Some(source),
            AnchorError::Note(e) => Some(e),
            _ => None,
        }
    }
}

impl From<NoteError> for AnchorError {
    fn from(e: NoteError) -> AnchorError {
        AnchorError::Note(e)
    }
}
