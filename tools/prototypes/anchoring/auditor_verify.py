#!/usr/bin/env python3
"""
auditor_verify.py - offline verification of a Stet anchor evidence bundle.
Needs only: python3 (stdlib) + openssl >= 3.0. No network access.

  python3 auditor_verify.py <bundle_dir> <trust_dir> [--min-tsa 2]

trust_dir holds ONE pinned root per TSA, named <tsa>.pem, obtained by the
auditor independently of the bundle (e.g. from the TSA's website / OS store,
fingerprint-checked), plus optionally log.vkey for the log's Ed25519 key.

Checks
  1. checkpoint body parses (origin / size / base64 root) and the log's
     Ed25519 signed-note signature verifies (if trust_dir/log.vkey present)
  2. for every token in bundle/tsa/*.tsr:
       openssl ts -verify -digest SHA256(body) -CAfile trust/<tsa>.pem -attime <genTime>
     -> signature, ESS cert binding, EKU timeStamping, chain to pinned root,
        cert validity *at genTime* (TSA certs expire; -attime avoids false failures)
  3. every proofs/*.json: recompute leaf from (tenant, run_id, seq, head) and
     verify the RFC 9162 inclusion proof against the checkpoint root
  4. policy: >= --min-tsa distinct TSAs verified; reports the anchoring time
     window [earliest genTime, latest genTime]
"""
import base64
import datetime as dt
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

OPENSSL = os.environ.get("OPENSSL", "openssl")
LEAF_DOMAIN = b"pragmatic/anchor-leaf/v1"


def leaf_hash(d):
    return hashlib.sha256(b"\x00" + d).digest()


def node_hash(l, r):
    return hashlib.sha256(b"\x01" + l + r).digest()


def verify_inclusion(i, n, lh, proof, root):          # RFC 9162 2.1.3.2
    if i >= n:
        return False
    fn, sn, r = i, n - 1, lh
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while True:
                    fn >>= 1; sn >>= 1
                    if fn & 1 or fn == 0:
                        break
        else:
            r = node_hash(r, p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r == root


def run(*a, inp=None):
    p = subprocess.run(a, input=inp, capture_output=True)
    return p.returncode, (p.stdout + p.stderr).decode(errors="replace")


def gen_time_epoch(tsr):
    rc, out = run(OPENSSL, "ts", "-reply", "-in", tsr, "-text")
    m = re.search(r"Time stamp: (\w{3}\s+\d+ \d\d:\d\d:\d\d)(\.\d+)? (\d{4}) GMT", out)
    if not m:
        raise ValueError("no genTime in " + tsr)
    t = dt.datetime.strptime(f"{m.group(1)} {m.group(3)}", "%b %d %H:%M:%S %Y").replace(tzinfo=dt.timezone.utc)
    return t, int(t.timestamp()) + 1          # +1s: round up past fractional seconds


def verify_note_sig(note: bytes, body: bytes, vkey_line: str):
    name, keyid_hex, b64 = vkey_line.strip().split("+", 2)
    raw = base64.b64decode(b64)
    assert raw[0] == 0x01, "only Ed25519 note keys supported"
    pub = raw[1:]
    keyid = bytes.fromhex(keyid_hex)
    for line in note.decode().split("\n"):
        if line.startswith("\u2014 " + name + " "):
            blob = base64.b64decode(line.split(" ", 2)[2])
            if blob[:4] != keyid:
                continue
            spki = bytes.fromhex("302a300506032b6570032100") + pub     # SubjectPublicKeyInfo for Ed25519
            with tempfile.TemporaryDirectory() as d:
                open(f"{d}/pub.der", "wb").write(spki)
                open(f"{d}/sig", "wb").write(blob[4:])
                open(f"{d}/msg", "wb").write(body)
                rc, out = run(OPENSSL, "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey",
                              f"{d}/pub.der", "-rawin", "-in", f"{d}/msg", "-sigfile", f"{d}/sig")
            return rc == 0
    return False


def main(bundle, trust, min_tsa=2):
    ok = True
    note = open(os.path.join(bundle, "checkpoint"), "rb").read()
    body = note.split(b"\n\n", 1)[0] + b"\n"
    lines = body.decode().rstrip("\n").split("\n")
    origin, size, root = lines[0], int(lines[1]), base64.b64decode(lines[2], validate=True)
    digest = hashlib.sha256(body).hexdigest()
    print(f"checkpoint  origin={origin} size={size} root={root.hex()}")
    print(f"anchored    sha256(checkpoint body)={digest}")
    vk = os.path.join(trust, "log.vkey")
    if os.path.exists(vk):
        s = verify_note_sig(note, body, open(vk).read())
        print(f"log sig     Ed25519 signed note: {'OK' if s else 'FAIL'}")
        ok &= s
    good, times = set(), []
    for tsr in sorted(glob.glob(os.path.join(bundle, "tsa", "*.tsr"))):
        name = os.path.basename(tsr)[:-4]
        anchor = os.path.join(trust, name + ".pem")
        if not os.path.exists(anchor):
            print(f"tsa {name:9s} SKIP (no pinned root in trust dir)")
            continue
        t, at = gen_time_epoch(tsr)
        rc, out = run(OPENSSL, "ts", "-verify", "-in", tsr, "-digest", digest,
                      "-CAfile", anchor, "-attime", str(at))
        passed = rc == 0 and "Verification: OK" in out
        errs = [l.split(":")[5] for l in out.splitlines() if ":error:" in l and l.count(":") >= 6]
        print(f"tsa {name:9s} {'OK  ' if passed else 'FAIL'} genTime={t.isoformat()}"
              + ("" if passed else "  " + "; ".join(errs)))
        if passed:
            good.add(name); times.append(t)
    proofs = sorted(glob.glob(os.path.join(bundle, "proofs", "*.json")))
    for pf in proofs:
        j = json.load(open(pf))
        if j["tree_size"] != size:
            print(f"proof {os.path.basename(pf)} FAIL tree_size mismatch"); ok = False; continue
        ld = (LEAF_DOMAIN + bytes.fromhex(j["tenant"]) + bytes.fromhex(j["run_id"])
              + j["seq"].to_bytes(8, "big") + bytes.fromhex(j["head"]))
        v = verify_inclusion(j["leaf_index"], size, leaf_hash(ld), [bytes.fromhex(p) for p in j["proof"]], root)
        print(f"proof run={j['run_id']} seq={j['seq']} head={j['head'][:16]}.. idx={j['leaf_index']}: {'OK' if v else 'FAIL'}")
        ok &= v
    if len(good) < min_tsa:
        print(f"POLICY FAIL: {len(good)} TSA(s) verified, need {min_tsa}")
        ok = False
    else:
        print(f"policy      {len(good)} independent TSAs verified ({', '.join(sorted(good))}); "
              f"existed no later than {min(times).isoformat()} (window {max(times) - min(times)})")
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    a = sys.argv
    mt = int(a[a.index("--min-tsa") + 1]) if "--min-tsa" in a else 2
    sys.exit(main(a[1], a[2], mt))
