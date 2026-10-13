//! An append-only RFC 6962 Merkle tree that answers root, inclusion and
//! consistency queries for logs of many millions of leaves without
//! rehashing them.
//!
//! The core's [`pragmatic::merkle`] functions take every leaf hash and
//! recompute the tree on each call. That is the reference, and the right
//! tool for small trees and for verification, but an anchor log grows by
//! every changed run every interval: tens of millions of leaves within a
//! year on a busy server. A proof must cost O(log n) work, and memory must
//! stay far below one hash per leaf.
//!
//! # What is cached
//!
//! Leaves are grouped in *chunks* of `2^chunk_bits` (256 by default). The
//! tree keeps:
//!
//! - the root of every complete chunk, and above them the root of every
//!   complete, aligned subtree (level `k` holds the subtrees of
//!   `2^(chunk_bits + k)` leaves), which is about two hashes per chunk;
//! - the leaf hashes of the last, incomplete chunk.
//!
//! That is roughly 0.25 bytes of memory per leaf. Any node a proof needs
//! is either one cached hash, a combination of O(log n) cached hashes (the
//! incomplete subtrees on a tree's right edge), or lies inside one chunk,
//! whose leaf hashes are read back from storage through a
//! [`LeafHashSource`]. A proof therefore reads at most two chunks.
//!
//! Every function computes the same values as the core's reference
//! implementation, node for node (the tests compare them exhaustively for
//! small trees and by sampling for large ones), and proofs verify with
//! [`pragmatic::merkle::verify_inclusion`] and
//! [`pragmatic::merkle::verify_consistency`].
//!
//! # Why the recursion only meets aligned ranges
//!
//! RFC 6962 splits `[lo, hi)` at `lo + k`, `k` the largest power of two
//! below `hi - lo`. Starting from `[0, n)`, every range the recursion
//! visits starts at a multiple of a power of two at least as large as the
//! range, so its left half is always a complete aligned subtree (a cached
//! hash, or a slice of one chunk), and only the right edge is incomplete.

use std::collections::HashMap;
use std::io;

use pragmatic::merkle;
use pragmatic::sha256::Digest;

use crate::error::AnchorError;

/// The default chunk size, as a power of two: 256 leaves per chunk.
pub const DEFAULT_CHUNK_BITS: u32 = 8;

/// Where the tree reads leaf hashes it does not keep in memory.
pub trait LeafHashSource {
    /// The leaf hashes of complete chunk `chunk`: exactly `2^chunk_bits`
    /// of them, for leaves `chunk << chunk_bits` onwards.
    fn chunk_leaf_hashes(&self, chunk: u64, chunk_bits: u32) -> io::Result<Vec<Digest>>;
}

/// An in-memory list of leaf hashes is a source (tests, small tools).
impl LeafHashSource for Vec<Digest> {
    fn chunk_leaf_hashes(&self, chunk: u64, chunk_bits: u32) -> io::Result<Vec<Digest>> {
        let start = (chunk << chunk_bits) as usize;
        let end = start + (1usize << chunk_bits);
        self.get(start..end).map(<[Digest]>::to_vec).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "chunk past the end of the leaves",
            )
        })
    }
}

/// A source for queries that never leave memory: roots at the tree's
/// current size. Reading from it is a bug.
pub(crate) struct NoSource;

impl LeafHashSource for NoSource {
    fn chunk_leaf_hashes(&self, _chunk: u64, _bits: u32) -> io::Result<Vec<Digest>> {
        Err(io::Error::other(
            "leaf hashes requested from an in-memory query",
        ))
    }
}

/// The cached tree. See the module documentation.
#[derive(Clone, Debug)]
pub struct TreeCache {
    chunk_bits: u32,
    size: u64,
    /// `levels[k][i]` is the root of leaves
    /// `[i << (chunk_bits + k), (i + 1) << (chunk_bits + k))`.
    levels: Vec<Vec<Digest>>,
    /// Leaf hashes of the incomplete last chunk.
    tail: Vec<Digest>,
}

impl Default for TreeCache {
    fn default() -> Self {
        TreeCache::new()
    }
}

/// Chunks read during one query, so a proof that touches the same chunk
/// for several siblings reads it once.
type ChunkCache = HashMap<u64, Vec<Digest>>;

impl TreeCache {
    /// An empty tree with the default chunk size.
    pub fn new() -> TreeCache {
        TreeCache::with_chunk_bits(DEFAULT_CHUNK_BITS)
    }

    /// An empty tree with chunks of `2^chunk_bits` leaves (1 to 16). Small
    /// chunks exercise the cached levels in tests; the default suits real
    /// logs.
    pub fn with_chunk_bits(chunk_bits: u32) -> TreeCache {
        assert!((1..=16).contains(&chunk_bits), "chunk_bits out of range");
        TreeCache {
            chunk_bits,
            size: 0,
            levels: Vec::new(),
            tail: Vec::new(),
        }
    }

    /// The number of leaves.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The chunk size as a power of two.
    pub fn chunk_bits(&self) -> u32 {
        self.chunk_bits
    }

    /// Hashes held in memory (cached subtree roots and tail leaf hashes).
    pub fn cached_hashes(&self) -> usize {
        self.levels.iter().map(Vec::len).sum::<usize>() + self.tail.len()
    }

    fn chunk_len(&self) -> u64 {
        1 << self.chunk_bits
    }

    /// Append one leaf hash ([`pragmatic::merkle::leaf_hash`] of the leaf
    /// data). Amortized O(1) hashes.
    pub fn push(&mut self, leaf_hash: Digest) {
        self.tail.push(leaf_hash);
        self.size += 1;
        if self.tail.len() as u64 == self.chunk_len() {
            let root = merkle::root(&self.tail);
            self.tail.clear();
            self.push_node(0, root);
        }
    }

    /// Record a complete subtree root at `level`, combining it with its
    /// left sibling into the parent whenever the pair is complete.
    fn push_node(&mut self, level: usize, hash: Digest) {
        if self.levels.len() == level {
            self.levels.push(Vec::new());
        }
        let nodes = &mut self.levels[level];
        nodes.push(hash);
        let n = nodes.len();
        if n.is_multiple_of(2) {
            let parent = merkle::node_hash(&nodes[n - 2], &nodes[n - 1]);
            self.push_node(level + 1, parent);
        }
    }

    /// Shrink the tree to its first `size` leaves (rolling back a batch
    /// whose checkpoint could not be stored). The chunk that becomes the
    /// new tail is read back from `source` if it was complete.
    pub fn truncate(&mut self, size: u64, source: &dyn LeafHashSource) -> io::Result<()> {
        if size >= self.size {
            return Ok(());
        }
        let bits = self.chunk_bits;
        let rem = (size & (self.chunk_len() - 1)) as usize;
        let new_tail = if rem == 0 {
            Vec::new()
        } else if size >> bits == self.size >> bits {
            self.tail[..rem].to_vec()
        } else {
            let mut leaves = source.chunk_leaf_hashes(size >> bits, bits)?;
            leaves.truncate(rem);
            leaves
        };
        for (k, nodes) in self.levels.iter_mut().enumerate() {
            nodes.truncate((size >> (bits + k as u32)) as usize);
        }
        while self.levels.last().is_some_and(Vec::is_empty) {
            self.levels.pop();
        }
        self.tail = new_tail;
        self.size = size;
        Ok(())
    }

    /// The root of the tree of the first `size` leaves (any size up to the
    /// current one). At the current size this never reads storage.
    pub fn root(&self, size: u64, source: &dyn LeafHashSource) -> Result<Digest, AnchorError> {
        self.check_size(size)?;
        if size == 0 {
            return Ok(merkle::empty_root());
        }
        let mut cache = ChunkCache::new();
        self.range_hash(0, size, source, &mut cache)
    }

    /// The inclusion proof (RFC 6962 `PATH`) for leaf `index` in the tree
    /// of the first `size` leaves.
    pub fn inclusion_proof(
        &self,
        index: u64,
        size: u64,
        source: &dyn LeafHashSource,
    ) -> Result<Vec<Digest>, AnchorError> {
        self.check_size(size)?;
        if index >= size {
            return Err(AnchorError::OutOfRange(format!(
                "leaf {index} is not in a tree of {size} leaves"
            )));
        }
        let mut cache = ChunkCache::new();
        let mut out = Vec::new();
        self.path(index, 0, size, source, &mut cache, &mut out)?;
        Ok(out)
    }

    /// The consistency proof (RFC 6962 `PROOF`) from the tree of the first
    /// `old` leaves to the tree of the first `new` leaves. Empty when
    /// `old` is 0 or equals `new`, as the core produces it.
    pub fn consistency_proof(
        &self,
        old: u64,
        new: u64,
        source: &dyn LeafHashSource,
    ) -> Result<Vec<Digest>, AnchorError> {
        self.check_size(new)?;
        if old > new {
            return Err(AnchorError::OutOfRange(format!(
                "no consistency proof from {old} leaves back to {new}"
            )));
        }
        let mut out = Vec::new();
        if old > 0 {
            let mut cache = ChunkCache::new();
            self.subproof(old, 0, new, true, source, &mut cache, &mut out)?;
        }
        Ok(out)
    }

    fn check_size(&self, size: u64) -> Result<(), AnchorError> {
        if size > self.size {
            return Err(AnchorError::OutOfRange(format!(
                "tree size {size} exceeds the log's {} leaves",
                self.size
            )));
        }
        Ok(())
    }

    /// `PATH(m, D[lo:hi])`, appended bottom-up.
    fn path(
        &self,
        m: u64,
        lo: u64,
        hi: u64,
        source: &dyn LeafHashSource,
        cache: &mut ChunkCache,
        out: &mut Vec<Digest>,
    ) -> Result<(), AnchorError> {
        let n = hi - lo;
        if n <= 1 {
            return Ok(());
        }
        let k = split_point(n);
        if m < lo + k {
            self.path(m, lo, lo + k, source, cache, out)?;
            out.push(self.range_hash(lo + k, hi, source, cache)?);
        } else {
            self.path(m, lo + k, hi, source, cache, out)?;
            out.push(self.range_hash(lo, lo + k, source, cache)?);
        }
        Ok(())
    }

    /// `SUBPROOF(m, D[lo:hi], whole)`, where `m` counts the old tree's
    /// leaves inside `[lo, hi)`.
    #[allow(clippy::too_many_arguments)]
    fn subproof(
        &self,
        m: u64,
        lo: u64,
        hi: u64,
        whole: bool,
        source: &dyn LeafHashSource,
        cache: &mut ChunkCache,
        out: &mut Vec<Digest>,
    ) -> Result<(), AnchorError> {
        let n = hi - lo;
        if m == n {
            if !whole {
                out.push(self.range_hash(lo, hi, source, cache)?);
            }
            return Ok(());
        }
        let k = split_point(n);
        if m <= k {
            self.subproof(m, lo, lo + k, whole, source, cache, out)?;
            out.push(self.range_hash(lo + k, hi, source, cache)?);
        } else {
            self.subproof(m - k, lo + k, hi, false, source, cache, out)?;
            out.push(self.range_hash(lo, lo + k, source, cache)?);
        }
        Ok(())
    }

    /// `MTH(D[lo:hi])` for a range the RFC 6962 recursion can visit.
    fn range_hash(
        &self,
        lo: u64,
        hi: u64,
        source: &dyn LeafHashSource,
        cache: &mut ChunkCache,
    ) -> Result<Digest, AnchorError> {
        let bits = self.chunk_bits;
        let n = hi - lo;
        // A complete aligned subtree of at least one chunk: cached.
        if n >= self.chunk_len() && n.is_power_of_two() && lo.is_multiple_of(n) {
            let height = n.trailing_zeros();
            return Ok(self.levels[(height - bits) as usize][(lo >> height) as usize]);
        }
        // Inside one chunk: hash its leaf hashes directly.
        if lo >> bits == (hi - 1) >> bits {
            let chunk = lo >> bits;
            let base = chunk << bits;
            let leaves = self.chunk_leaves(chunk, source, cache)?;
            return Ok(merkle::root(
                &leaves[(lo - base) as usize..(hi - base) as usize],
            ));
        }
        let k = split_point(n);
        let left = self.range_hash(lo, lo + k, source, cache)?;
        let right = self.range_hash(lo + k, hi, source, cache)?;
        Ok(merkle::node_hash(&left, &right))
    }

    /// The leaf hashes of `chunk`: the in-memory tail, or a complete chunk
    /// read from `source` (once per query).
    fn chunk_leaves<'c>(
        &'c self,
        chunk: u64,
        source: &dyn LeafHashSource,
        cache: &'c mut ChunkCache,
    ) -> Result<&'c [Digest], AnchorError> {
        if chunk == self.size >> self.chunk_bits {
            return Ok(&self.tail);
        }
        if let std::collections::hash_map::Entry::Vacant(slot) = cache.entry(chunk) {
            let leaves = source
                .chunk_leaf_hashes(chunk, self.chunk_bits)
                .map_err(AnchorError::io(format!("reading leaf chunk {chunk}")))?;
            if leaves.len() as u64 != self.chunk_len() {
                return Err(AnchorError::Corrupt(format!(
                    "leaf chunk {chunk} has {} leaves",
                    leaves.len()
                )));
            }
            slot.insert(leaves);
        }
        Ok(&cache[&chunk])
    }
}

/// The largest power of two strictly less than `n` (`n >= 2`).
fn split_point(n: u64) -> u64 {
    debug_assert!(n >= 2);
    1 << (63 - (n - 1).leading_zeros())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pragmatic::merkle::{
        consistency_proof, inclusion_proof, leaf_hash, root, verify_consistency, verify_inclusion,
    };

    fn leaves(n: u64) -> Vec<Digest> {
        (0..n).map(|i| leaf_hash(&i.to_le_bytes())).collect()
    }

    fn tree(leaves: &[Digest], bits: u32) -> TreeCache {
        let mut t = TreeCache::with_chunk_bits(bits);
        for l in leaves {
            t.push(*l);
        }
        t
    }

    /// Every root, inclusion proof and consistency proof of every tree up
    /// to 40 leaves equals the core's reference, for several chunk sizes
    /// (so complete chunks, cached levels and tails all take part).
    #[test]
    fn matches_the_reference_exhaustively_for_small_trees() {
        let all = leaves(40);
        for bits in [1, 2, 3] {
            let t = tree(&all, bits);
            let src = &all;
            for n in 0..=40u64 {
                let prefix = &all[..n as usize];
                assert_eq!(
                    t.root(n, src).unwrap(),
                    root(prefix),
                    "root n={n} bits={bits}"
                );
                for i in 0..n {
                    assert_eq!(
                        t.inclusion_proof(i, n, src).unwrap(),
                        inclusion_proof(i as usize, prefix).unwrap(),
                        "inclusion i={i} n={n} bits={bits}"
                    );
                }
                for m in 0..=n {
                    assert_eq!(
                        t.consistency_proof(m, n, src).unwrap(),
                        consistency_proof(m as usize, prefix).unwrap(),
                        "consistency m={m} n={n} bits={bits}"
                    );
                }
            }
        }
    }

    /// A 100,000-leaf log: every sampled proof verifies with the core's
    /// verifiers, the current root matches the reference, and the cache
    /// holds a small fraction of the leaves.
    #[test]
    fn proofs_verify_on_a_large_log() {
        let n = 100_000u64;
        let all = leaves(n);
        let t = tree(&all, DEFAULT_CHUNK_BITS);
        let src = &all;
        let full_root = t.root(n, &NoSource).unwrap();
        assert_eq!(full_root, root(&all));
        assert!(
            t.cached_hashes() < (n / 100) as usize,
            "{}",
            t.cached_hashes()
        );

        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = |bound: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % bound
        };
        for _ in 0..300 {
            let size = 1 + next(n);
            let index = next(size);
            let size_root = t.root(size, src).unwrap();
            let proof = t.inclusion_proof(index, size, src).unwrap();
            assert!(verify_inclusion(
                &all[index as usize],
                index,
                size,
                &proof,
                &size_root
            ));
            let old = next(size + 1);
            let old_root = t.root(old, src).unwrap();
            let cproof = t.consistency_proof(old, n, src).unwrap();
            assert!(verify_consistency(old, n, &old_root, &full_root, &cproof));
        }
        // Spot-check against the reference at a few awkward sizes.
        for size in [257u64, 65_537] {
            let prefix = &all[..size as usize];
            assert_eq!(t.root(size, src).unwrap(), root(prefix));
            assert_eq!(
                t.inclusion_proof(size - 1, size, src).unwrap(),
                inclusion_proof(size as usize - 1, prefix).unwrap()
            );
            assert_eq!(
                t.consistency_proof(size / 3, size, src).unwrap(),
                consistency_proof(size as usize / 3, prefix).unwrap()
            );
        }
    }

    /// Scale check, run on demand (`cargo test --release -p
    /// pragmatic-anchor -- --ignored`): four million leaves, with proofs
    /// that read at most two chunks each.
    #[test]
    #[ignore]
    fn four_million_leaves() {
        let n = 4_000_000u64;
        let all = leaves(n);
        let started = std::time::Instant::now();
        let t = tree(&all, DEFAULT_CHUNK_BITS);
        let built = started.elapsed();
        let full = t.root(n, &NoSource).unwrap();
        let started = std::time::Instant::now();
        for k in 0..1000u64 {
            let size = n - k * 997;
            let index = (k * 7919) % size;
            let proof = t.inclusion_proof(index, size, &all).unwrap();
            let root = t.root(size, &all).unwrap();
            assert!(verify_inclusion(
                &all[index as usize],
                index,
                size,
                &proof,
                &root
            ));
            let c = t.consistency_proof(size, n, &all).unwrap();
            assert!(verify_consistency(size, n, &root, &full, &c));
        }
        eprintln!(
            "4M leaves: built in {built:?}, 1000 inclusion+root+consistency in {:?}, {} cached hashes",
            started.elapsed(),
            t.cached_hashes()
        );
    }

    #[test]
    fn current_root_never_reads_storage() {
        let all = leaves(1000);
        let mut t = TreeCache::with_chunk_bits(3);
        for (i, l) in all.iter().enumerate() {
            t.push(*l);
            let size = i as u64 + 1;
            assert_eq!(t.root(size, &NoSource).unwrap(), root(&all[..=i]));
        }
    }

    #[test]
    fn truncate_restores_an_earlier_tree() {
        let all = leaves(300);
        for bits in [2, 3, 8] {
            for keep in [0u64, 1, 7, 8, 9, 64, 128, 200, 299, 300] {
                let mut t = tree(&all, bits);
                let src = &all;
                t.truncate(keep, src).unwrap();
                assert_eq!(t.size(), keep);
                assert_eq!(
                    t.root(keep, &NoSource).unwrap(),
                    root(&all[..keep as usize])
                );
                // Growing again gives the same tree as never truncating.
                for l in &all[keep as usize..] {
                    t.push(*l);
                }
                let fresh = tree(&all, bits);
                assert_eq!(
                    t.root(300, &NoSource).unwrap(),
                    fresh.root(300, &NoSource).unwrap()
                );
                assert_eq!(t.cached_hashes(), fresh.cached_hashes());
            }
        }
    }

    #[test]
    fn queries_beyond_the_tree_are_errors() {
        let all = leaves(10);
        let t = tree(&all, 2);
        let src = &all;
        assert!(t.root(11, src).is_err());
        assert!(t.inclusion_proof(10, 10, src).is_err());
        assert!(t.inclusion_proof(0, 11, src).is_err());
        assert!(t.consistency_proof(5, 4, src).is_err());
        assert!(t.consistency_proof(5, 11, src).is_err());
        assert_eq!(t.root(0, src).unwrap(), merkle::empty_root());
    }
}
