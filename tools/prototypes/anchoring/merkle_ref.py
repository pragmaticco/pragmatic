#!/usr/bin/env python3
"""
merkle_ref.py - RFC 6962 / RFC 9162 Merkle tree hashing, inclusion and
consistency proofs, plus a Pragmatic leaf encoding with domain separation.
Zero dependencies. Template for the Rust port.

Tree hashing (RFC 9162 2.1.1, identical to RFC 6962 2.1):
  MTH({})        = SHA-256()                       (empty tree)
  leaf hash      = SHA-256(0x00 || leaf_data)
  node hash      = SHA-256(0x01 || left || right)
  MTH(D[n]), n>1 : k = largest power of two < n
                   = node(MTH(D[0:k]), MTH(D[k:n]))
  Odd tails are NOT duplicated (avoids the Bitcoin CVE-2012-2459 ambiguity).

Pragmatic leaf_data (proposal, v1), fixed 96 bytes, no parsing ambiguity:
  domain   : 24 bytes  b"pragmatic/anchor-leaf/v1" (exactly 24 ASCII bytes)
  tenant   : 16 bytes  tenant/deployment id (UUID bytes)
  run_id   : 16 bytes  run UUID
  seq      :  8 bytes  big-endian index of the last journal entry covered
  head     : 32 bytes  SHA-256 chain head after entry `seq`
"""
import base64
import hashlib
import sys

LEAF_DOMAIN = b"pragmatic/anchor-leaf/v1"
assert len(LEAF_DOMAIN) == 24


def leaf_data(tenant: bytes, run_id: bytes, seq: int, head: bytes) -> bytes:
    assert len(tenant) == 16 and len(run_id) == 16 and len(head) == 32
    return LEAF_DOMAIN + tenant + run_id + seq.to_bytes(8, "big") + head


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _k(n: int) -> int:
    """largest power of two strictly less than n (n > 1)"""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def mth(leaf_hashes: list) -> bytes:
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = _k(n)
    return node_hash(mth(leaf_hashes[:k]), mth(leaf_hashes[k:]))


def inclusion_proof(m: int, leaf_hashes: list) -> list:
    """PATH(m, D[n]) from RFC 9162 2.1.3.1"""
    n = len(leaf_hashes)
    if n <= 1:
        return []
    k = _k(n)
    if m < k:
        return inclusion_proof(m, leaf_hashes[:k]) + [mth(leaf_hashes[k:])]
    return inclusion_proof(m - k, leaf_hashes[k:]) + [mth(leaf_hashes[:k])]


def verify_inclusion(leaf_index: int, tree_size: int, lh: bytes, proof: list, root: bytes) -> bool:
    """RFC 9162 2.1.3.2 verification algorithm (iterative, what Rust should port)."""
    if leaf_index >= tree_size:
        return False
    fn, sn = leaf_index, tree_size - 1
    r = lh
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while True:
                    fn >>= 1
                    sn >>= 1
                    if fn & 1 or fn == 0:
                        break
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def consistency_proof(m: int, leaf_hashes: list) -> list:
    """PROOF(m, D[n]) from RFC 9162 2.1.4.1"""
    def subproof(m, d, b):
        n = len(d)
        if m == n:
            return [] if b else [mth(d)]
        k = _k(n)
        if m <= k:
            return subproof(m, d[:k], b) + [mth(d[k:])]
        return subproof(m - k, d[k:], False) + [mth(d[:k])]
    if m == 0 or m == len(leaf_hashes):
        return []
    return subproof(m, leaf_hashes, True)


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes, proof: list) -> bool:
    """RFC 9162 2.1.4.2 verification algorithm."""
    if first == second:
        return not proof and first_root == second_root
    if first == 0 or first > second or not proof:
        return False
    if first & (first - 1) == 0:          # first is an exact power of 2
        proof = [first_root] + proof
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while True:
                    fn >>= 1
                    sn >>= 1
                    if fn & 1 or fn == 0:
                        break
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


def checkpoint_body(origin: str, size: int, root: bytes, extra_lines=()) -> bytes:
    """C2SP tlog-checkpoint note body: origin, decimal size, base64 root, optional extension lines."""
    lines = [origin, str(size), base64.b64encode(root).decode()] + list(extra_lines)
    return ("\n".join(lines) + "\n").encode()


def _selftest():
    import os
    ok = 0
    # RFC 6962 / CT test vectors (from certificate-transparency-go merkletree tests):
    # leaves: "", 00, 10, 2021, 3031, 40414243, 5051525354555657, 606162636465666768696a6b6c6d6e6f
    vec = [b"", bytes.fromhex("00"), bytes.fromhex("10"), bytes.fromhex("2021"), bytes.fromhex("3031"),
           bytes.fromhex("40414243"), bytes.fromhex("5051525354555657"),
           bytes.fromhex("606162636465666768696a6b6c6d6e6f")]
    expected_roots = {
        1: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        2: "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        3: "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        4: "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        5: "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        6: "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        7: "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        8: "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    }
    lhs = [leaf_hash(v) for v in vec]
    for n, exp in expected_roots.items():
        got = mth(lhs[:n]).hex()
        assert got == exp, (n, got, exp)
        ok += 1
    # exhaustive proof round-trips on random trees
    for n in range(1, 70):
        L = [leaf_hash(os.urandom(8)) for _ in range(n)]
        root = mth(L)
        for i in range(n):
            pr = inclusion_proof(i, L)
            assert verify_inclusion(i, n, L[i], pr, root)
            assert not verify_inclusion(i, n, leaf_hash(b"x"), pr, root)
            if pr:
                bad = list(pr)
                bad[0] = bytes(32)
                assert not verify_inclusion(i, n, L[i], bad, root)
            ok += 1
        for m in range(1, n + 1):
            cp = consistency_proof(m, L)
            assert verify_consistency(m, n, mth(L[:m]), root, cp), (m, n)
            if m < n:
                # a forged first root (history rewritten) must not verify
                assert not verify_consistency(m, n, bytes(32), root, cp), (m, n)
                # nor must the proof verify against a different second root
                assert not verify_consistency(m, n, mth(L[:m]), bytes(32), cp), (m, n)
            ok += 1
    print(f"selftest OK ({ok} checks, CT vectors 1..8 match)")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        _selftest()
