#!/usr/bin/env python3
"""Generate the anchored evidence-bundle fixtures.

    python3 generate.py

Writes, next to this script:

  local.json            the unanchored local bundle the Rust example wrote
  bundle.json           the same journal anchored three times, signed
  bundle-hmac.json      the same, with the anchor log naming the run by HMAC
  log.json              the full anchor log at the latest checkpoint
  witness-log.json      the fixture witness's cosigned history
  rogue.json            time-stamp tokens over bundle.json's anchor digests
                        from a self-signed TSA, with its certificate
  trust/                pinned inputs: the log key, the witness key, a wrong
                        witness key with the same name, and the roots of
                        two independent TSAs

Everything a server and its witnesses would produce is built here, with
the Python standard library and the openssl command line only, so the
fixtures do not come from the Rust code they test:

- the journal and its records come from `cargo run -p pragmatic --example
  evidence_fixture` (the journal format is the one thing that must be
  produced by the implementation);
- the anchor log, inclusion and consistency proofs, leaves and checkpoint
  bodies are computed here from RFC 6962 and design section 4.7;
- Ed25519 signatures (checkpoints, cosignatures, the bundle signature) are
  made with `openssl pkeyutl` from fixed, public seeds, so they are the
  same on every run;
- the two TSAs are throwaway OpenSSL CAs, each with a time-stamping
  certificate (critical extendedKeyUsage timeStamping), and every token is
  a real `openssl ts -reply`.

Slot salts, TSA keys and genTimes differ on every run, so rerunning the
generator changes every file; commit them together. The seeds and keys sign
nothing but these fixtures.
"""

import base64
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", ".."))
OPENSSL = os.environ.get("OPENSSL", "openssl")

ORIGIN = "pragmatic/fixture.example"
WITNESS = "witness.fixture.example"
RUN_ID = "support-ticket-4127"
PKCS8_ED25519 = bytes.fromhex("302e020100300506032b657004220420")
TYPE_ED25519 = 0x01
TYPE_COSIGNATURE = 0x04
NO_PREVIOUS = 2**64 - 1


def run(*args, cwd=None, stdin=None):
    p = subprocess.run(args, cwd=cwd, input=stdin, capture_output=True)
    if p.returncode != 0:
        sys.exit(f"{' '.join(args)} failed:\n{p.stderr.decode(errors='replace')}")
    return p.stdout


def b64(data):
    return base64.b64encode(data).decode()


def sha256(data):
    return hashlib.sha256(data).digest()


# -- Ed25519 through OpenSSL ---------------------------------------------------


class Key:
    """An Ed25519 key derived from a fixed seed, signing with openssl."""

    def __init__(self, work, label, name, sig_type):
        self.name = name
        self.type = sig_type
        seed = sha256(b"pragmatic evidence fixture: " + label.encode())
        self.path = os.path.join(work, label + ".der")
        with open(self.path, "wb") as f:
            f.write(PKCS8_ED25519 + seed)
        der = run(OPENSSL, "pkey", "-inform", "DER", "-in", self.path, "-pubout", "-outform", "DER")
        self.public = der[-32:]
        h = sha256(name.encode() + b"\n" + bytes([sig_type]) + self.public)
        self.key_id = h[:4]
        self.work = work

    def vkey(self):
        return f"{self.name}+{self.key_id.hex()}+{b64(bytes([self.type]) + self.public)}"

    def sign(self, message):
        msg = os.path.join(self.work, "message")
        sig = os.path.join(self.work, "signature")
        with open(msg, "wb") as f:
            f.write(message)
        run(OPENSSL, "pkeyutl", "-sign", "-inkey", self.path, "-keyform", "DER",
            "-rawin", "-in", msg, "-out", sig)
        with open(sig, "rb") as f:
            return f.read()

    def note_line(self, body):
        return f"\u2014 {self.name} {b64(self.key_id + self.sign(body.encode()))}"

    def cosignature_line(self, body, timestamp):
        message = f"cosignature/v1\ntime {timestamp}\n{body}".encode()
        ts = timestamp.to_bytes(8, "big")
        return f"\u2014 {self.name} {b64(self.key_id + ts + self.sign(message))}"


# -- RFC 6962 Merkle trees -----------------------------------------------------


def leaf_hash(data):
    return sha256(b"\x00" + data)


def node_hash(left, right):
    return sha256(b"\x01" + left + right)


def split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(hashes):
    if not hashes:
        return sha256(b"")
    if len(hashes) == 1:
        return hashes[0]
    k = split(len(hashes))
    return node_hash(mth(hashes[:k]), mth(hashes[k:]))


def inclusion(m, hashes):
    if len(hashes) <= 1:
        return []
    k = split(len(hashes))
    if m < k:
        return inclusion(m, hashes[:k]) + [mth(hashes[k:])]
    return inclusion(m - k, hashes[k:]) + [mth(hashes[:k])]


def consistency(m, hashes):
    def sub(m, h, whole):
        if m == len(h):
            return [] if whole else [mth(h)]
        k = split(len(h))
        if m <= k:
            return sub(m, h[:k], whole) + [mth(h[k:])]
        return sub(m - k, h[k:], False) + [mth(h[:k])]

    if m == 0 or m == len(hashes):
        return []
    return sub(m, hashes, True)


def leaf(kind, ident, entries, head, prev):
    return (b"pragmatic/v2/leaf" + bytes([kind]) + len(ident).to_bytes(4, "little") + ident
            + entries.to_bytes(8, "little") + head
            + (NO_PREVIOUS if prev is None else prev).to_bytes(8, "little"))


# -- RFC 3161 through OpenSSL ---------------------------------------------------

TSA_EXT = """
[tsa_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
extendedKeyUsage = critical, timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""

TSA_SECTION = """
[{name}]
dir = {dir}
serial = $dir/{name}.serial
crypto_device = builtin
signer_cert = $dir/{name}-tsa.pem
certs = $dir/{name}-tsa.pem
signer_key = $dir/{name}-tsa.key
signer_digest = sha256
default_policy = 1.3.6.1.4.1.57264.99.1
digests = sha256
accuracy = secs:1, millisecs:500
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""


class Tsa:
    """A throwaway time-stamping authority: a root CA and a TSA certificate
    with critical extendedKeyUsage timeStamping, or (rogue) a self-signed
    TSA certificate that chains to nothing anyone pins."""

    def __init__(self, work, name, label, rogue=False):
        self.work, self.name = work, name
        ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"]
        subj = f"/O=Pragmatic Fixtures/CN={label}"
        if rogue:
            run(OPENSSL, "req", "-x509", *ec, "-keyout", f"{name}-tsa.key", "-out", f"{name}-tsa.pem",
                "-days", "36500", "-subj", subj + " TSA",
                "-addext", "basicConstraints=critical,CA:FALSE",
                "-addext", "keyUsage=critical,digitalSignature",
                "-addext", "extendedKeyUsage=critical,timeStamping", cwd=work)
            self.root = None
        else:
            run(OPENSSL, "req", "-x509", *ec, "-keyout", f"{name}-root.key", "-out", f"{name}-root.pem",
                "-days", "36500", "-subj", subj + " Root",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", cwd=work)
            run(OPENSSL, "req", "-new", *ec, "-keyout", f"{name}-tsa.key", "-out", f"{name}-tsa.csr",
                "-subj", subj + " TSA", cwd=work)
            with open(os.path.join(work, "tsa-ext.cnf"), "w") as f:
                f.write(TSA_EXT)
            run(OPENSSL, "x509", "-req", "-in", f"{name}-tsa.csr", "-CA", f"{name}-root.pem",
                "-CAkey", f"{name}-root.key", "-set_serial", "2", "-days", "36500",
                "-extfile", "tsa-ext.cnf", "-extensions", "tsa_ext", "-out", f"{name}-tsa.pem", cwd=work)
            self.root = read_text(os.path.join(work, f"{name}-root.pem"))
        with open(os.path.join(work, f"{name}.serial"), "w") as f:
            f.write("01\n")
        with open(os.path.join(work, f"{name}.cnf"), "w") as f:
            f.write(TSA_SECTION.format(name=name, dir=work))
        self.cert = read_text(os.path.join(work, f"{name}-tsa.pem"))

    def stamp(self, digest):
        run(OPENSSL, "ts", "-query", "-digest", digest.hex(), "-sha256", "-cert",
            "-out", "query.tsq", cwd=self.work)
        run(OPENSSL, "ts", "-reply", "-config", f"{self.name}.cnf", "-section", self.name,
            "-queryfile", "query.tsq", "-token_out", "-out", "token.der", cwd=self.work)
        with open(os.path.join(self.work, "token.der"), "rb") as f:
            return f.read()


def read_text(path):
    with open(path) as f:
        return f.read()


# -- the bundle ------------------------------------------------------------------


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def anchored(local, keys, tsas, anchor_key):
    """The local bundle anchored three times in a log shared with other
    runs, as a server would build it. Returns (bundle, log leaves,
    cosigned checkpoints)."""
    log_key, witness = keys
    heads = [bytes.fromhex(r["hash"]) for r in local["records"]]
    entries = len(heads)
    ours = RUN_ID.encode() if anchor_key is None else hmac.new(anchor_key, RUN_ID.encode(), "sha256").digest()

    leaves, last = [], {}

    def add(kind, ident, n, head):
        key = (kind, ident)
        data = leaf(kind, ident, n, head, last.get(key))
        last[key] = len(leaves)
        leaves.append(data)
        return len(leaves) - 1

    def other(ident, n):
        return (0, ident, n, sha256(ident + b":" + str(n).encode()))

    # Each batch appends its leaves in (type, id) order and ends in a
    # checkpoint (design 4.7). Our run is anchored at 6 entries, at 20, and
    # in full; a last batch of other runs follows, so the latest checkpoint
    # is larger than any of ours.
    batches = [
        [other(b"billing-1", 4), (0, ours, 6, heads[5]), (1, b"access", 10, sha256(b"access:10"))],
        [other(b"billing-2", 9), (0, ours, 20, heads[19]), other(b"zeta-7", 2)],
        [other(b"billing-1", 11), (0, ours, entries, heads[-1]), (1, b"access", 31, sha256(b"access:31"))],
        [other(b"billing-3", 1), other(b"billing-4", 5)],
    ]
    ours_at, sizes = [], []
    for batch in batches:
        for kind, ident, n, head in sorted(batch, key=lambda x: (x[0], x[1])):
            index = add(kind, ident, n, head)
            if ident == ours:
                ours_at.append((len(sizes), index))
        sizes.append(len(leaves))
    hashes = [leaf_hash(x) for x in leaves]

    def checkpoint(size):
        body = f"{ORIGIN}\n{size}\n{b64(mth(hashes[:size]))}\n"
        return body, body + "\n" + log_key.note_line(body) + "\n"

    latest_size = sizes[-1]
    _, latest = checkpoint(latest_size)
    anchors, cosigned = [], []
    for seq, size in enumerate(sizes):
        body, note = checkpoint(size)
        line = witness.cosignature_line(body, 1_791_900_000 + 600 * seq)
        cosigned.append(note + line + "\n")
    for seq, index in ours_at:
        size = sizes[seq]
        body, note = checkpoint(size)
        digest = sha256(body.encode())
        witnesses = [
            {"type": "rfc3161", "tsa": f"https://{t.name}.fixture.example/tsr", "operator": label,
             "token": b64(t.stamp(digest)), "certs_pem": t.cert}
            for t, label in tsas
        ]
        witnesses.append({"type": "cosignature", "name": WITNESS,
                          "line": witness.cosignature_line(body, 1_791_900_000 + 600 * seq)})
        anchors.append({
            "seq": seq,
            "tree_size": size,
            "leaf_index": index,
            "leaf": leaves[index].hex(),
            "inclusion_proof": [h.hex() for h in inclusion(index, hashes[:size])],
            "root": mth(hashes[:size]).hex(),
            "checkpoint": note,
            "anchor_digest": digest.hex(),
            "consistency_to_latest": [h.hex() for h in consistency(size, hashes[:latest_size])],
            "witnesses": witnesses,
        })

    bundle = dict(local)
    bundle.update({
        "generated_at": "2026-10-13T12:00:00Z",
        "generator": "pragmatic-server 0.6.0 (fixture)",
        "requested_by": "tok_auditor_fixture",
        "anchor_id": None if anchor_key is None else anchor_key.hex(),
        "independent": True,
        "anchors": anchors,
        "latest_checkpoint": latest,
        "verification_spec": spec(),
    })
    bundle.pop("signature", None)
    message = sha256(canonical(bundle).encode())
    bundle["signature"] = {
        "key_id": log_key.key_id.hex(),
        "public_key": log_key.public.hex(),
        "value": log_key.sign(message).hex(),
    }
    return bundle, leaves, cosigned


def spec():
    path = os.path.join(REPO, "docs", "evidence-format.md")
    data = open(path, "rb").read() if os.path.exists(path) else b""
    return {
        "url": "https://github.com/pragmaticco/pragmatic/blob/v0.6.0/docs/evidence-format.md",
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def write_json(name, value):
    with open(os.path.join(HERE, name), "w", encoding="utf-8") as f:
        f.write(json.dumps(value, indent=1, sort_keys=True, ensure_ascii=False) + "\n")


def main():
    if shutil.which(OPENSSL) is None:
        sys.exit("openssl is not on PATH")
    work = tempfile.mkdtemp(prefix="pragmatic-evidence-fixture-")
    try:
        local_path = os.path.join(work, "local.json")
        run("cargo", "run", "-q", "-p", "pragmatic", "--example", "evidence_fixture", "--",
            local_path, cwd=REPO)
        local = json.loads(read_text(local_path))
        log_key = Key(work, "log", ORIGIN, TYPE_ED25519)
        witness = Key(work, "witness", WITNESS, TYPE_COSIGNATURE)
        wrong = Key(work, "wrong-witness", WITNESS, TYPE_COSIGNATURE)
        tsa_a = Tsa(work, "tsa-a", "Fixture TSA A")
        tsa_b = Tsa(work, "tsa-b", "Fixture TSA B")
        rogue = Tsa(work, "rogue", "Rogue", rogue=True)
        tsas = [(tsa_a, "Fixture TSA A"), (tsa_b, "Fixture TSA B")]

        bundle, leaves, cosigned = anchored(local, (log_key, witness), tsas, None)
        hmac_key = sha256(b"pragmatic evidence fixture: anchor key")
        bundle_hmac, _, _ = anchored(local, (log_key, witness), tsas, hmac_key)

        write_json("local.json", local)
        write_json("bundle.json", bundle)
        write_json("bundle-hmac.json", bundle_hmac)
        write_json("log.json", {"leaves": [x.hex() for x in leaves]})
        write_json("witness-log.json", {"witness": WITNESS, "origin": ORIGIN, "checkpoints": cosigned})
        write_json("rogue.json", {
            "certs_pem": rogue.cert,
            "tokens": {str(a["seq"]): b64(rogue.stamp(bytes.fromhex(a["anchor_digest"])))
                       for a in bundle["anchors"]},
        })
        trust = os.path.join(HERE, "trust")
        os.makedirs(trust, exist_ok=True)
        for name, text in [
            ("log.vkey", log_key.vkey()),
            ("witness.vkey", witness.vkey()),
            ("witness-wrong.vkey", wrong.vkey()),
        ]:
            with open(os.path.join(trust, name), "w") as f:
                f.write(text + "\n")
        for name, tsa in [("tsa-a-root.pem", tsa_a), ("tsa-b-root.pem", tsa_b)]:
            with open(os.path.join(trust, name), "w") as f:
                f.write(tsa.root)
        print(f"wrote fixtures for {len(bundle['anchors'])} anchors over "
              f"{bundle['journal']['entries']} entries; log of {len(leaves)} leaves")
    finally:
        shutil.rmtree(work)


if __name__ == "__main__":
    main()
