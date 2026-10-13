//! RFC 6962 Merkle trees over SHA-256: roots, inclusion proofs and
//! consistency proofs.
//!
//! Pragmatic Server anchors many journals at once by building a Merkle tree
//! whose leaves commit to each run's head, then timestamping only the root.
//! An evidence bundle then carries one leaf plus its audit path, and anyone
//! can check that the run was part of the anchored batch without seeing the
//! other runs. Using exactly the Certificate Transparency construction
//! (RFC 6962 section 2.1, restated in RFC 9162 section 2.1) means auditors
//! can verify bundles with existing CT tooling and that the domain
//! separation questions have already been settled in public:
//!
//! - leaves are hashed as `SHA-256(0x00 ‖ data)` and interior nodes as
//!   `SHA-256(0x01 ‖ left ‖ right)`, so a leaf can never be passed off as an
//!   interior node (the second-preimage attack on naive Merkle trees);
//! - the tree is split at the largest power of two strictly less than the
//!   number of leaves, so trees of every size are well defined and a tree
//!   only ever grows by appending on the right, which is what makes
//!   consistency proofs between two sizes possible.
//!
//! The functions here take *leaf hashes* (the output of [`leaf_hash`]), not
//! raw leaf data, because that is what the server stores per batch and what
//! an evidence bundle carries.
//!
//! Proof generation follows the recursive definitions of RFC 6962 section
//! 2.1.1 (`PATH`) and 2.1.2 (`PROOF`/`SUBPROOF`). Verification follows the
//! iterative algorithms of RFC 9162 sections 2.1.3.2 and 2.1.4.2 step by
//! step; they need only the proof, the sizes and the roots, never the tree.

use crate::sha256::{sha256, Digest, Sha256};

/// Hash a leaf: `SHA-256(0x00 ‖ data)`.
pub fn leaf_hash(data: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(&[0x00]);
    h.update(data);
    h.finalize()
}

/// Hash an interior node: `SHA-256(0x01 ‖ left ‖ right)`.
pub fn node_hash(left: &Digest, right: &Digest) -> Digest {
    let mut h = Sha256::new();
    h.update(&[0x01]);
    h.update(left);
    h.update(right);
    h.finalize()
}

/// The root of the empty tree: `SHA-256("")`, per RFC 6962 section 2.1.
pub fn empty_root() -> Digest {
    sha256(b"")
}

/// The largest power of two strictly less than `n`. Requires `n >= 2`.
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// The Merkle Tree Hash (`MTH`) of a list of leaf hashes.
///
/// An empty list hashes to [`empty_root`]; a single leaf hash is its own
/// root. Runs in O(n) hashes with O(log n) recursion depth.
pub fn root(leaves: &[Digest]) -> Digest {
    match leaves.len() {
        0 => empty_root(),
        _ => subtree_root(leaves),
    }
}

/// The roots of the trees made of the first `s` leaves, for each `s` in
/// `sizes`, in the order given: `prefix_roots(leaves, &[s])[0]` equals
/// `root(&leaves[..s])`, and a size beyond `leaves.len()` gives `None`.
///
/// An auditor holding a log's full leaf list uses this to check every tree
/// head a witness cosigned against the list itself. Recomputing [`root`]
/// for each size would cost O(n) hashes per size; this makes one pass over
/// the leaves, keeping the *frontier* (the roots of the perfect subtrees
/// that a tree of the current size splits into, largest first), so it
/// costs O(n) hashes plus O(log n) per size. The root of a tree is its
/// frontier folded from the right, `node(P1, node(P2, ... node(Pk-1, Pk)))`,
/// which is RFC 6962's split at the largest power of two below the size,
/// applied recursively.
pub fn prefix_roots(leaves: &[Digest], sizes: &[u64]) -> Vec<Option<Digest>> {
    let mut order: Vec<usize> = (0..sizes.len()).collect();
    order.sort_by_key(|&i| sizes[i]);
    let mut out = vec![None; sizes.len()];
    // (root, height) of each perfect subtree, left to right.
    let mut frontier: Vec<(Digest, u32)> = Vec::new();
    let mut size = 0u64;
    let mut pending = order.into_iter().peekable();
    while let Some(&i) = pending.peek() {
        if sizes[i] == size {
            out[i] = Some(fold_frontier(&frontier));
            pending.next();
            continue;
        }
        let Some(leaf) = leaves.get(size as usize) else {
            break; // every remaining size is beyond the leaves
        };
        let mut node = *leaf;
        let mut height = 0;
        while let Some(&(left, h)) = frontier.last() {
            if h != height {
                break;
            }
            frontier.pop();
            node = node_hash(&left, &node);
            height += 1;
        }
        frontier.push((node, height));
        size += 1;
    }
    out
}

/// The root of a tree from its frontier (see [`prefix_roots`]).
fn fold_frontier(frontier: &[(Digest, u32)]) -> Digest {
    let mut subtrees = frontier.iter().rev();
    let Some(&(mut acc, _)) = subtrees.next() else {
        return empty_root();
    };
    for (left, _) in subtrees {
        acc = node_hash(left, &acc);
    }
    acc
}

/// `MTH` for a non-empty list.
fn subtree_root(leaves: &[Digest]) -> Digest {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let k = split_point(leaves.len());
    node_hash(&subtree_root(&leaves[..k]), &subtree_root(&leaves[k..]))
}

/// The audit path proving that `leaves[index]` is in the tree of all
/// `leaves` (RFC 6962 `PATH(m, D[n])`), ordered from the leaf's sibling up
/// to the child of the root.
///
/// Returns `None` if `index` is out of range. A one-leaf tree has an empty
/// path.
pub fn inclusion_proof(index: usize, leaves: &[Digest]) -> Option<Vec<Digest>> {
    if index >= leaves.len() {
        return None;
    }
    let mut path = Vec::new();
    push_path(index, leaves, &mut path);
    Some(path)
}

/// Append `PATH(m, D[n])` to `out`. The recursion builds the path from the
/// bottom up: the deeper sub-path first, then this level's sibling.
fn push_path(m: usize, leaves: &[Digest], out: &mut Vec<Digest>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split_point(n);
    if m < k {
        push_path(m, &leaves[..k], out);
        out.push(subtree_root(&leaves[k..]));
    } else {
        push_path(m - k, &leaves[k..], out);
        out.push(subtree_root(&leaves[..k]));
    }
}

/// Verify an inclusion proof (RFC 9162 section 2.1.3.2).
///
/// Returns true only if `proof` shows that `leaf_hash` sits at `index` in a
/// tree of `tree_size` leaves whose root is `root`. Proofs that are too
/// short, too long, or for an out-of-range index are rejected.
pub fn verify_inclusion(
    leaf_hash: &Digest,
    index: u64,
    tree_size: u64,
    proof: &[Digest],
    root: &Digest,
) -> bool {
    // 1. The index must lie inside the tree.
    if index >= tree_size {
        return false;
    }
    // 2-3. `fnode` tracks our node's index and `snode` the last node's index
    // at the current level; `r` is the running hash.
    let mut fnode = index;
    let mut snode = tree_size - 1;
    let mut r = *leaf_hash;
    // 4. Fold in each sibling.
    for p in proof {
        // a. A proof longer than the tree is tall cannot be valid.
        if snode == 0 {
            return false;
        }
        // b. Our node is a right child (odd index), or the last node of a
        // level with no right sibling (it gets promoted, so the sibling we
        // are given belongs to an ancestor and sits on the left).
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            // Skip the levels where our node was promoted without a sibling.
            while fnode & 1 == 0 && fnode != 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        // c. Move up a level.
        fnode >>= 1;
        snode >>= 1;
    }
    // 5. We must have reached the root exactly, and it must match.
    snode == 0 && r == *root
}

/// The consistency proof that a tree of the first `m` leaves is a prefix of
/// the tree of all `leaves` (RFC 6962 `PROOF(m, D[n])`).
///
/// Returns `None` if `m` exceeds the number of leaves. The proof is empty
/// when `m == 0` (the empty tree is a prefix of every tree) or when
/// `m == leaves.len()` (a tree is consistent with itself).
pub fn consistency_proof(m: usize, leaves: &[Digest]) -> Option<Vec<Digest>> {
    if m > leaves.len() {
        return None;
    }
    let mut proof = Vec::new();
    if m > 0 {
        push_subproof(m, leaves, true, &mut proof);
    }
    Some(proof)
}

/// Append `SUBPROOF(m, D[n], b)` to `out`. `whole` is RFC 6962's `b`: true
/// while the subtree being described is exactly the old tree's left edge,
/// whose root the verifier already knows and so need not be sent.
fn push_subproof(m: usize, leaves: &[Digest], whole: bool, out: &mut Vec<Digest>) {
    let n = leaves.len();
    if m == n {
        if !whole {
            out.push(subtree_root(leaves));
        }
        return;
    }
    let k = split_point(n);
    if m <= k {
        push_subproof(m, &leaves[..k], whole, out);
        out.push(subtree_root(&leaves[k..]));
    } else {
        push_subproof(m - k, &leaves[k..], false, out);
        out.push(subtree_root(&leaves[..k]));
    }
}

/// Verify a consistency proof between a tree of `m` leaves with root
/// `root_m` and a tree of `n` leaves with root `root_n`
/// (RFC 9162 section 2.1.4.2).
///
/// The degenerate cases the RFC leaves to the caller are handled the way
/// [`consistency_proof`] produces them: `m == 0` needs an empty proof and
/// `root_m` equal to [`empty_root`] (and `root_n` too when `n == 0`), and
/// `m == n` needs an empty proof and equal roots. `m > n` is always
/// rejected.
pub fn verify_consistency(
    m: u64,
    n: u64,
    root_m: &Digest,
    root_n: &Digest,
    proof: &[Digest],
) -> bool {
    if m > n {
        return false;
    }
    // The empty-tree case comes first, so that `m == n == 0` cannot vouch
    // for an arbitrary root as the root of the empty tree.
    if m == 0 {
        let empty = empty_root();
        return proof.is_empty() && *root_m == empty && (n > 0 || *root_n == empty);
    }
    if m == n {
        return proof.is_empty() && root_m == root_n;
    }
    // 1. Between distinct non-empty sizes the proof is never empty.
    if proof.is_empty() {
        return false;
    }
    // 2. When m is a power of two the old root is a node of the new tree and
    // is not sent; the RFC prepends it. We avoid the allocation by choosing
    // the starting hash and the remaining path directly.
    let (start, rest) = if m.is_power_of_two() {
        (*root_m, proof)
    } else {
        (proof[0], &proof[1..])
    };
    // 3. Indices of the old tree's last node and the new tree's last node.
    let mut fnode = m - 1;
    let mut snode = n - 1;
    // 4. Climb past the levels where the old tree's last node is a right
    // child: those siblings are inside the old tree and already in `start`.
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    // 5. `fr` rebuilds the old root and `sr` the new one.
    let mut fr = start;
    let mut sr = start;
    // 6. Fold in the remaining hashes.
    for c in rest {
        // a. A proof longer than the new tree is tall cannot be valid.
        if snode == 0 {
            return false;
        }
        // b. A left sibling belongs to both trees; a right sibling only to
        // the new one.
        if fnode & 1 == 1 || fnode == snode {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while fnode & 1 == 0 && fnode != 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        // c. Move up a level.
        fnode >>= 1;
        snode >>= 1;
    }
    // 7. Both roots must be reproduced and the climb must end at the top.
    fr == *root_m && sr == *root_n && snode == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd-length hex");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn digest(s: &str) -> Digest {
        unhex(s).try_into().unwrap()
    }

    // Test vectors from the Certificate Transparency reference
    // implementation, google/certificate-transparency,
    // cpp/merkletree/merkle_tree_test.cc (kInputs, kSHA256Roots,
    // kSHA256Paths, kSHA256Proofs), and the same leaves and roots in
    // transparency-dev/merkle, testonly/constants.go (LeafInputs,
    // RootHashes, NodeHashes).

    /// The eight leaf inputs, hex-encoded.
    const INPUTS: [&str; 8] = [
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    ];

    /// Roots of the trees over the first 1..=8 inputs.
    const ROOTS: [&str; 8] = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];

    /// Leaf hashes of the eight inputs (NodeHashes level 0).
    const LEAF_HASHES: [&str; 8] = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        "0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
        "07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7",
        "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        "4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658",
        "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
        "46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1",
    ];

    /// Inclusion vectors as (0-based leaf index, tree size, path). The C++
    /// source numbers leaves from 1; they are converted here.
    const PATHS: [(usize, usize, &[&str]); 5] = [
        (0, 1, &[]),
        (
            0,
            8,
            &[
                "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
            ],
        ),
        (
            5,
            8,
            &[
                "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
                "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            ],
        ),
        (
            2,
            3,
            &["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"],
        ),
        (
            1,
            5,
            &[
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            ],
        ),
    ];

    /// Consistency vectors as (old size, new size, proof).
    const PROOFS: [(usize, usize, &[&str]); 4] = [
        (1, 1, &[]),
        (
            1,
            8,
            &[
                "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
            ],
        ),
        (
            6,
            8,
            &[
                "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
                "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            ],
        ),
        (
            2,
            5,
            &[
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            ],
        ),
    ];

    fn vector_leaves() -> Vec<Digest> {
        INPUTS.iter().map(|s| leaf_hash(&unhex(s))).collect()
    }

    fn digests(hexes: &[&str]) -> Vec<Digest> {
        hexes.iter().map(|s| digest(s)).collect()
    }

    /// Distinct synthetic leaves for the property tests.
    fn synthetic_leaves(n: usize) -> Vec<Digest> {
        (0..n as u32).map(|i| leaf_hash(&i.to_le_bytes())).collect()
    }

    fn flip(d: &Digest) -> Digest {
        let mut t = *d;
        t[0] ^= 1;
        t
    }

    #[test]
    fn empty_tree_is_hash_of_empty_string() {
        assert_eq!(
            root(&[]),
            digest("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn leaf_hashes_match_vectors() {
        assert_eq!(vector_leaves(), digests(&LEAF_HASHES));
    }

    #[test]
    fn roots_match_vectors_for_every_prefix() {
        let leaves = vector_leaves();
        for (size, expected) in (1..=8).zip(ROOTS) {
            assert_eq!(root(&leaves[..size]), digest(expected), "size {size}");
        }
    }

    #[test]
    fn inclusion_proofs_match_vectors() {
        let leaves = vector_leaves();
        for (index, size, path) in PATHS {
            let expected = digests(path);
            let tree = &leaves[..size];
            assert_eq!(inclusion_proof(index, tree).unwrap(), expected);
            let r = root(tree);
            assert!(verify_inclusion(
                &leaves[index],
                index as u64,
                size as u64,
                &expected,
                &r
            ));
        }
    }

    #[test]
    fn consistency_proofs_match_vectors() {
        let leaves = vector_leaves();
        for (m, n, proof) in PROOFS {
            let expected = digests(proof);
            assert_eq!(consistency_proof(m, &leaves[..n]).unwrap(), expected);
            assert!(verify_consistency(
                m as u64,
                n as u64,
                &root(&leaves[..m]),
                &root(&leaves[..n]),
                &expected
            ));
        }
    }

    #[test]
    fn every_inclusion_proof_verifies_up_to_64_leaves() {
        for n in 1..=64usize {
            let leaves = synthetic_leaves(n);
            let r = root(&leaves);
            for i in 0..n {
                let proof = inclusion_proof(i, &leaves).unwrap();
                assert!(
                    verify_inclusion(&leaves[i], i as u64, n as u64, &proof, &r),
                    "n={n} i={i}"
                );
            }
        }
    }

    #[test]
    fn tampered_inclusion_proofs_fail() {
        for n in 1..=33usize {
            let leaves = synthetic_leaves(n);
            let r = root(&leaves);
            for i in 0..n {
                let proof = inclusion_proof(i, &leaves).unwrap();
                let (leaf, idx, size) = (&leaves[i], i as u64, n as u64);
                // Any changed sibling.
                for j in 0..proof.len() {
                    let mut bad = proof.clone();
                    bad[j] = flip(&bad[j]);
                    assert!(!verify_inclusion(leaf, idx, size, &bad, &r));
                }
                // Wrong leaf, wrong root.
                assert!(!verify_inclusion(&flip(leaf), idx, size, &proof, &r));
                assert!(!verify_inclusion(leaf, idx, size, &proof, &flip(&r)));
                // Truncated and extended paths.
                if !proof.is_empty() {
                    let short = &proof[..proof.len() - 1];
                    assert!(!verify_inclusion(leaf, idx, size, short, &r));
                }
                let mut long = proof.clone();
                long.push(r);
                assert!(!verify_inclusion(leaf, idx, size, &long, &r));
                // Every other claimed position.
                for k in 0..n as u64 {
                    if k != idx {
                        assert!(
                            !verify_inclusion(leaf, k, size, &proof, &r),
                            "n={n} i={i} k={k}"
                        );
                    }
                }
                // Out-of-range index.
                assert!(!verify_inclusion(leaf, size, size, &proof, &r));
            }
        }
    }

    #[test]
    fn inclusion_proof_rejects_out_of_range_index() {
        assert_eq!(inclusion_proof(0, &[]), None);
        assert_eq!(inclusion_proof(3, &synthetic_leaves(3)), None);
        assert!(!verify_inclusion(&[0; 32], 0, 0, &[], &empty_root()));
    }

    #[test]
    fn every_consistency_proof_verifies_up_to_32_leaves() {
        let all = synthetic_leaves(32);
        let roots: Vec<Digest> = (0..=32).map(|k| root(&all[..k])).collect();
        for n in 0..=32usize {
            for m in 0..=n {
                let proof = consistency_proof(m, &all[..n]).unwrap();
                assert!(
                    verify_consistency(m as u64, n as u64, &roots[m], &roots[n], &proof),
                    "m={m} n={n}"
                );
            }
        }
    }

    #[test]
    fn tampered_consistency_proofs_fail() {
        let all = synthetic_leaves(32);
        let roots: Vec<Digest> = (0..=32).map(|k| root(&all[..k])).collect();
        for n in 1..=32usize {
            for m in 1..n {
                let proof = consistency_proof(m, &all[..n]).unwrap();
                let (mm, nn) = (m as u64, n as u64);
                for j in 0..proof.len() {
                    let mut bad = proof.clone();
                    bad[j] = flip(&bad[j]);
                    assert!(!verify_consistency(mm, nn, &roots[m], &roots[n], &bad));
                }
                assert!(!verify_consistency(
                    mm,
                    nn,
                    &flip(&roots[m]),
                    &roots[n],
                    &proof
                ));
                assert!(!verify_consistency(
                    mm,
                    nn,
                    &roots[m],
                    &flip(&roots[n]),
                    &proof
                ));
                assert!(!verify_consistency(mm, nn, &roots[m], &roots[n], &[]));
                let short = &proof[..proof.len() - 1];
                assert!(!verify_consistency(mm, nn, &roots[m], &roots[n], short));
                let mut long = proof.clone();
                long.push(roots[n]);
                assert!(!verify_consistency(mm, nn, &roots[m], &roots[n], &long));
                // The proof for (m, n) must not pass for a different old size.
                for k in 1..n {
                    if k != m {
                        assert!(
                            !verify_consistency(k as u64, nn, &roots[k], &roots[n], &proof),
                            "m={m} n={n} k={k}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn consistency_degenerate_cases() {
        let leaves = synthetic_leaves(5);
        let r5 = root(&leaves);
        assert_eq!(consistency_proof(6, &leaves), None);
        assert_eq!(consistency_proof(0, &leaves), Some(vec![]));
        assert_eq!(consistency_proof(5, &leaves), Some(vec![]));
        // Equal sizes need equal roots and an empty proof.
        assert!(verify_consistency(5, 5, &r5, &r5, &[]));
        assert!(!verify_consistency(5, 5, &r5, &flip(&r5), &[]));
        assert!(!verify_consistency(5, 5, &r5, &r5, &[r5]));
        // The empty tree is a prefix of everything, but only with its own root.
        assert!(verify_consistency(0, 5, &empty_root(), &r5, &[]));
        assert!(!verify_consistency(0, 5, &r5, &r5, &[]));
        assert!(!verify_consistency(0, 5, &empty_root(), &r5, &[r5]));
        // Shrinking is never consistent.
        assert!(!verify_consistency(5, 4, &r5, &root(&leaves[..4]), &[]));
        // Two empty trees are consistent only under the empty root.
        let empty = empty_root();
        assert!(verify_consistency(0, 0, &empty, &empty, &[]));
        assert!(!verify_consistency(0, 0, &r5, &r5, &[]));
        assert!(!verify_consistency(0, 0, &empty, &r5, &[]));
        assert!(!verify_consistency(0, 0, &r5, &empty, &[]));
        assert!(!verify_consistency(0, 0, &empty, &empty, &[empty]));
    }

    #[test]
    fn prefix_roots_equal_the_roots_of_prefixes() {
        let leaves = synthetic_leaves(70);
        let sizes: Vec<u64> = (0..=72).rev().collect();
        let roots = prefix_roots(&leaves, &sizes);
        for (s, r) in sizes.iter().zip(&roots) {
            let want = (*s as usize <= leaves.len()).then(|| root(&leaves[..*s as usize]));
            assert_eq!(*r, want, "size {s}");
        }
        // Repeated sizes, in any order, and the RFC 6962 vectors.
        let v = vector_leaves();
        let got = prefix_roots(&v, &[8, 3, 8, 0]);
        assert_eq!(got[0], Some(digest(ROOTS[7])));
        assert_eq!(got[1], Some(digest(ROOTS[2])));
        assert_eq!(got[2], got[0]);
        assert_eq!(got[3], Some(empty_root()));
        assert!(prefix_roots(&[], &[]).is_empty());
    }

    #[test]
    fn large_tree_round_trips() {
        // Sizes around a power of two exercise the split at every level.
        for n in [1000usize, 1023, 1024, 1025] {
            let leaves = synthetic_leaves(n);
            let r = root(&leaves);
            for i in [0, 1, n / 2, n - 2, n - 1] {
                let proof = inclusion_proof(i, &leaves).unwrap();
                assert!(proof.len() <= 11);
                assert!(verify_inclusion(&leaves[i], i as u64, n as u64, &proof, &r));
            }
            for m in [1, 7, 512, n - 1] {
                let proof = consistency_proof(m, &leaves).unwrap();
                let rm = root(&leaves[..m]);
                assert!(verify_consistency(m as u64, n as u64, &rm, &r, &proof));
            }
        }
    }
}
