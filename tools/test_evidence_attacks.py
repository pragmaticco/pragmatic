#!/usr/bin/env python3
"""Attacks on evidence bundles, run against both verifiers.

Each test builds an adversarial bundle with the fixture generator's own
building blocks (crates/pragmatic/tests/fixtures/evidence/generate.py) plus
two fresh throwaway TSAs, runs BOTH verifiers (target/debug/pragmatic
verify-evidence and tools/verify_evidence.py) and asserts what a sound
verifier reports. test_attack_* are attacks an operator, or someone in the
middle, could mount; test_agree_* are bundles the two verifiers once read
differently; test_control_* show the attack is caught when the trick is
not used.

    cargo build -p pragmatic-cli
    python3 -I tools/test_evidence_attacks.py -v

Needs OpenSSL 3 on PATH; skips otherwise.
"""

import base64
import copy
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
FIX = os.path.join(REPO, "crates", "pragmatic", "tests", "fixtures", "evidence")
sys.path.insert(0, FIX)
sys.path.insert(0, HERE)
import generate as gen  # noqa: E402
import verify_evidence as vf  # noqa: E402

PRAGMATIC = os.path.join(REPO, "target", "debug", "pragmatic")
VERIFY_PY = os.path.join(HERE, "verify_evidence.py")
RUN = gen.RUN_ID
ORIGIN = gen.ORIGIN
NOW = 1_791_900_000


def b64(x):
    return base64.b64encode(x).decode()


def load_local():
    with open(os.path.join(FIX, "local.json"), encoding="utf-8") as f:
        return json.load(f)


def journal_of(local):
    return base64.b64decode(local["journal"]["data"])


def rewrite_journal(data, cursor, slot, new_content):
    """The operator's rewrite of an anchored entry: new content, a fresh
    commitment, and every chain link after it recomputed."""
    entries, heads = vf.parse_journal(data)
    s = entries[cursor]["slots"][slot]
    assert s["state"] == "sealed"
    s["content"] = new_content
    s["commitment"] = vf.commitment(s["salt"], new_content)
    out, head = bytearray(data[:16]), heads[0]
    for e in entries:
        rec = vf.encode_record(e)
        head = vf.sha256(head + e["cursor"].to_bytes(8, "little") + vf.skeleton(e))
        out += len(rec).to_bytes(4, "little") + rec + head
    return bytes(out)


def heads_of(data):
    return vf.parse_journal(data)[1]


class Log:
    """An RFC 6962 anchor log with leaves as design 4.7 defines them."""

    def __init__(self, origin, key):
        self.origin, self.key = origin, key
        self.leaves, self.last = [], {}

    def add(self, kind, ident, n, head, prev="auto"):
        if prev == "auto":
            prev = self.last.get((kind, ident))
        self.last[(kind, ident)] = len(self.leaves)
        self.leaves.append(gen.leaf(kind, ident, n, head, prev))
        return len(self.leaves) - 1

    def other(self, name, n):
        ident = name.encode()
        return self.add(0, ident, n, gen.sha256(ident + b":" + str(n).encode()))

    def hashes(self, size):
        return [gen.leaf_hash(x) for x in self.leaves[:size]]

    def body(self, size):
        return f"{self.origin}\n{size}\n{b64(gen.mth(self.hashes(size)))}\n"

    def note(self, size):
        body = self.body(size)
        return body + "\n" + self.key.note_line(body) + "\n"


class Attacks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if vf.openssl_binary()[0] is None:
            raise unittest.SkipTest("no usable openssl on PATH")
        if not os.path.exists(PRAGMATIC):
            raise unittest.SkipTest("build target/debug/pragmatic first")
        cls.work = tempfile.mkdtemp(prefix="pragmatic-review-attacks-")
        w = cls.work
        # The fixture's own keys (derived from public seeds): the auditor
        # pins trust/log.vkey and trust/witness.vkey.
        cls.log_key = gen.Key(w, "log", ORIGIN, gen.TYPE_ED25519)
        cls.witness = gen.Key(w, "witness", gen.WITNESS, gen.TYPE_COSIGNATURE)
        cls.mitm = gen.Key(w, "mitm", ORIGIN, gen.TYPE_ED25519)
        cls.tsas = [(gen.Tsa(w, "ra", "Review TSA A"), "Review TSA A"),
                    (gen.Tsa(w, "rb", "Review TSA B"), "Review TSA B")]
        cls.tsa_args = ["--tsa-roots", "review-a=" + os.path.join(w, "ra-root.pem"),
                        "--tsa-roots", "review-b=" + os.path.join(w, "rb-root.pem")]
        cls.witness_args = ["--witness-key", "fixture-witness=" + cls.witness.vkey()]
        cls.logkey_args = ["--log-key", cls.log_key.vkey()]
        cls.local = load_local()
        cls.honest = journal_of(cls.local)
        # Cursor 11 (anchored in every anchor of the honest run) said the
        # invoice was 49.00; the operator rewrites it.
        cls.forged = rewrite_journal(cls.honest, 11, 0, b'{"amount":"4900.00","charges":2}')
        cls.n = len(heads_of(cls.honest)) - 1

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    # -- building ---------------------------------------------------------

    def tsa_witnesses(self, digest):
        return [{"type": "rfc3161", "tsa": f"https://{t.name}.review.example/tsr",
                 "operator": label, "token": b64(t.stamp(digest)), "certs_pem": t.cert}
                for t, label in self.tsas]

    def cosig(self, body, ts):
        return {"type": "cosignature", "name": gen.WITNESS,
                "line": self.witness.cosignature_line(body, ts)}

    def anchor(self, log, seq, size, index, latest, witnesses):
        body = log.body(size)
        digest = gen.sha256(body.encode())
        hashes = log.hashes(latest)
        return {
            "seq": seq, "tree_size": size, "leaf_index": index,
            "leaf": log.leaves[index].hex(),
            "inclusion_proof": [h.hex() for h in gen.inclusion(index, hashes[:size])],
            "root": gen.mth(hashes[:size]).hex(),
            "checkpoint": log.note(size),
            "anchor_digest": digest.hex(),
            "consistency_to_latest": [h.hex() for h in gen.consistency(size, hashes)],
            "witnesses": witnesses(body, digest),
        }

    def bundle(self, journal, anchors, latest, anchor_id=None, sign_with=None):
        entries, heads = vf.parse_journal(journal)
        b = copy.deepcopy(self.local)
        b["journal"] = {"encoding": "base64", "data": b64(journal),
                        "entries": len(entries), "head": heads[-1].hex()}
        b["records"] = [vf.record_of(e) for e in entries]
        b.update({"generated_at": "2026-10-13T12:00:00Z", "generator": "pragmatic-server 0.6.0",
                  "requested_by": "tok_auditor", "independent": True, "anchors": anchors,
                  "anchor_id": None if anchor_id is None else anchor_id.hex(),
                  "latest_checkpoint": latest, "verification_spec": gen.spec(), "signature": None})
        if sign_with is not None:
            b.pop("signature")
            msg = gen.sha256(gen.canonical(b).encode())
            b["signature"] = {"key_id": sign_with.key_id.hex(), "public_key": sign_with.public.hex(),
                              "value": sign_with.sign(msg).hex()}
        return b

    def write(self, name, value):
        path = os.path.join(self.work, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))
        return path

    def rust(self, path, *args):
        p = subprocess.run([PRAGMATIC, "verify-evidence", path, *args],
                           capture_output=True, text=True)
        return p.returncode, p.stdout

    def py(self, path, *args):
        p = subprocess.run([sys.executable, "-I", VERIFY_PY, path, *args],
                           capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr

    def honest_log(self, ident, witness_log=True):
        """The run anchored honestly at 6, 20 and all entries, in three
        batches each cosigned by the witness. Returns (log, sizes, cosigned
        history)."""
        h = heads_of(self.honest)
        log = Log(ORIGIN, self.log_key)
        sizes = []
        log.other("billing-1", 4)
        log.add(0, ident, 6, h[6])
        sizes.append(len(log.leaves))
        log.other("billing-2", 9)
        log.add(0, ident, 20, h[20])
        sizes.append(len(log.leaves))
        log.add(0, ident, self.n, h[self.n])
        log.other("billing-3", 1)
        sizes.append(len(log.leaves))
        return log, sizes

    def witness_log(self, log, sizes, origin=ORIGIN):
        notes = []
        for i, s in enumerate(sizes):
            notes.append(log.note(s) + self.witness.cosignature_line(log.body(s), NOW + 600 * i) + "\n")
        return {"witness": gen.WITNESS, "origin": origin, "checkpoints": notes}

    # -- 1. HMAC run ids: the bundle chooses k_run -------------------------

    def rekeyed(self, k_real, k_fake):
        """The run is honestly anchored under k_real; the operator then
        rewrites cursor 11 and anchors the forged journal as a fresh leaf
        chain under k_fake, appended to the same log and cosigned."""
        id_real = RUN.encode() if k_real is None else hmac.new(k_real, RUN.encode(), "sha256").digest()
        id_fake = RUN.encode() if k_fake is None else hmac.new(k_fake, RUN.encode(), "sha256").digest()
        log, sizes = self.honest_log(id_real)
        f = heads_of(self.forged)
        index = log.add(0, id_fake, self.n, f[self.n], prev=None)
        log.other("zeta-7", 2)
        sizes.append(len(log.leaves))
        latest = sizes[-1]
        a = self.anchor(log, 3, latest, index, latest,
                        lambda body, d: self.tsa_witnesses(d) + [self.cosig(body, NOW + 1800)])
        b = self.bundle(self.forged, [a], log.note(latest), anchor_id=k_fake, sign_with=self.log_key)
        paths = (self.write("rekey.json", b),
                 self.write("rekey-log.json", {"leaves": [x.hex() for x in log.leaves]}),
                 self.write("rekey-wlog.json", self.witness_log(log, sizes)))
        return paths

    def audit_args(self, log_path, wlog_path):
        return (self.tsa_args + self.witness_args + self.logkey_args
                + ["--log", log_path, "--witness-log", wlog_path])

    def test_attack_hmac_rekey_rust(self):
        bundle, log, wlog = self.rekeyed(gen.sha256(b"real k_run"), gen.sha256(b"fresh k_run"))
        code, out = self.rust(bundle, *self.audit_args(log, wlog))
        self.assertNotEqual(code, 0, "a rewritten, re-anchored journal must not be VERIFIED "
                            "when --log holds the run's original leaves:\n" + out)

    def test_attack_hmac_rekey_python(self):
        bundle, log, wlog = self.rekeyed(gen.sha256(b"real k_run"), gen.sha256(b"fresh k_run"))
        code, out = self.py(bundle, *self.audit_args(log, wlog))
        self.assertNotEqual(code, 0, out)

    def test_control_plain_ids_catch_the_same_rewrite(self):
        bundle, log, wlog = self.rekeyed(None, None)
        code, out = self.rust(bundle, *self.audit_args(log, wlog))
        self.assertEqual(code, 1, out)
        self.assertIn("anchor_omitted", out)

    # -- 2. witness log of another origin: the audit is skipped -----------

    def forked(self, origin, filler_to):
        """The operator forks the log (same signing key) and anchors the
        rewritten journal in the fork, witnessed by two TSAs (which stamp
        anything); the honest history was cosigned by the witness."""
        honest, sizes = self.honest_log(RUN.encode())
        f = heads_of(self.forged)
        fork = Log(origin, self.log_key)
        fork.leaves.append(honest.leaves[0])  # shares the first leaf
        index = fork.add(0, RUN.encode(), self.n, f[self.n], prev=None)
        fork.other("filler-0", 1)
        anchored = len(fork.leaves)
        i = 1
        while len(fork.leaves) < filler_to:
            fork.other(f"filler-{i}", 1)
            i += 1
        latest = len(fork.leaves)
        a = self.anchor(fork, 7, anchored, index, latest, lambda body, d: self.tsa_witnesses(d))
        b = self.bundle(self.forged, [a], fork.note(latest), sign_with=self.log_key)
        return (self.write(f"fork-{filler_to}.json", b),
                self.write(f"fork-{filler_to}-log.json", {"leaves": [x.hex() for x in fork.leaves]}),
                self.write(f"fork-{filler_to}-wlog.json", self.witness_log(honest, sizes)),
                sizes, anchored, latest)

    def test_attack_fork_under_another_origin(self):
        bundle, log, wlog, _, _, _ = self.forked(ORIGIN + "-mirror", 3)
        for name, run in (("rust", self.rust), ("python", self.py)):
            code, out = run(bundle, *self.audit_args(log, wlog))
            self.assertNotEqual(code, 0, f"{name}: the requested --witness-log audit was skipped, "
                                f"yet the forked bundle is VERIFIED:\n{out}")

    def test_attack_fork_at_sizes_the_witness_never_cosigned(self):
        bundle, log, wlog, sizes, anchored, latest = self.forked(ORIGIN, 8)
        # Honest cosigned sizes are 2, 4 and 6; the fork's are 3 and 8, and
        # --log holds the fork's leaves 0..8, from which the fork's roots at
        # 2, 4 and 6 differ from what the witness cosigned.
        self.assertEqual((sizes, anchored, latest), ([2, 4, 6], 3, 8))
        for name, run in (("rust", self.rust), ("python", self.py)):
            code, out = run(bundle, *self.audit_args(log, wlog))
            self.assertNotEqual(code, 0, f"{name}: forked log passes --log and --witness-log:\n{out}")

    def test_attack_witness_log_without_cosignatures(self):
        # A witness log whose checkpoints carry no valid cosignature at all
        # is accepted as the witness's history.
        honest, sizes = self.honest_log(RUN.encode())
        a = self.anchor(honest, 0, sizes[0], 1, sizes[-1],
                        lambda body, d: self.tsa_witnesses(d) + [self.cosig(body, NOW)])
        # Anchored at 6 entries: PARTIAL is the honest verdict.
        b = self.bundle(self.honest, [a], honest.note(sizes[-1]), sign_with=self.log_key)
        bogus = {"witness": gen.WITNESS, "origin": ORIGIN,
                 "checkpoints": [honest.body(s) + "\n\u2014 " + gen.WITNESS + " AAAAAAE=\n" for s in sizes]}
        path, wlog = self.write("wl.json", b), self.write("wl-bogus.json", bogus)
        code, out = self.rust(path, *self.tsa_args, *self.witness_args, *self.logkey_args,
                              "--witness-log", wlog)
        self.assertNotIn("[pass] 11 witness log", out,
                         "a witness log with no verifiable cosignature passes step 11:\n" + out)
        self.assertEqual(code, 1, out)
        self.assertIn("witness_log_untrusted", out)
        pcode, pout = self.py(path, *self.tsa_args, *self.witness_args, *self.logkey_args,
                              "--witness-log", wlog)
        self.assertEqual(pcode, 1, pout)
        self.assertIn("witness_log_untrusted", pout)

    # -- 3. one operator backdates the reported time ------------------------

    def test_attack_single_operator_backdating(self):
        log = Log(ORIGIN, self.log_key)
        log.other("billing-1", 4)
        index = log.add(0, RUN.encode(), self.n, heads_of(self.forged)[self.n])
        size = len(log.leaves)
        backdated = 1_577_836_800  # 2020-01-01T00:00:00Z, signed by ONE operator
        a = self.anchor(log, 0, size, index, size,
                        lambda body, d: self.tsa_witnesses(d) + [self.cosig(body, backdated)])
        b = self.bundle(self.forged, [a], log.note(size), sign_with=self.log_key)
        code, out = self.rust(self.write("backdate.json", b),
                              *self.tsa_args, *self.witness_args, *self.logkey_args)
        self.assertEqual(code, 0, out)
        anchor_line = next(l for l in out.splitlines() if l.startswith("  anchor 0:"))
        # Two TSAs (two of the three operators) say the checkpoint existed
        # only now; one witness says 2020. With independence set at two
        # operators, the time two operators vouch for is the TSAs' time.
        self.assertNotIn("2020-01-01", anchor_line, anchor_line)
        self.assertIn("no later than 2026-", anchor_line)
        pcode, pout = self.py(self.work + "/backdate.json",
                              *self.tsa_args, *self.witness_args, *self.logkey_args)
        self.assertEqual(pcode, 0, pout)
        line = next(l for l in pout.splitlines() if l.startswith("  anchor 0:"))
        self.assertNotIn("2020-01-01", line, line)
        self.assertIn("no later than 2026-", line)

    # -- 3b. an anchor of zero entries makes any journal "VERIFIED (PARTIAL)"

    def test_attack_zero_entry_anchor(self):
        # Design 4.7: runs created by PUT are anchored even with zero
        # entries, so a genuine leaf (run id, 0 entries, the constant unkeyed
        # genesis head) exists for the run. Its head is the same for every
        # unkeyed journal, so it vouches for no content at all; attached to a
        # fabricated journal it still yields exit 2.
        genesis = heads_of(self.forged)[0]
        log = Log(ORIGIN, self.log_key)
        log.other("billing-1", 4)
        index = log.add(0, RUN.encode(), 0, genesis)
        size = len(log.leaves)
        a = self.anchor(log, 0, size, index, size,
                        lambda body, d: self.tsa_witnesses(d) + [self.cosig(body, NOW)])
        # Signed, as the operator's bundles are: with the log key pinned an
        # unsigned bundle fails on that alone.
        path = self.write("zero.json", self.bundle(self.forged, [a], log.note(size),
                                                   sign_with=self.log_key))
        for name, run in (("rust", self.rust), ("python", self.py)):
            code, out = run(path, *self.tsa_args, *self.witness_args, *self.logkey_args)
            self.assertEqual(code, 3, f"{name}: nothing of this journal is anchored, so the verdict "
                             f"must be UNANCHORED (3), not VERIFIED (PARTIAL):\n{out}")

    # -- 4. the reference verifier ignores a pinned log key -----------------

    def test_attack_log_built_without_the_log_key(self):
        # Someone without the log key builds a log for a rewritten journal,
        # signs it with a key that merely carries the log's name, and has
        # two public TSAs stamp it.
        log = Log(ORIGIN, self.mitm)
        log.other("billing-1", 4)
        index = log.add(0, RUN.encode(), self.n, heads_of(self.forged)[self.n])
        size = len(log.leaves)
        a = self.anchor(log, 0, size, index, size, lambda body, d: self.tsa_witnesses(d))
        path = self.write("mitm.json", self.bundle(self.forged, [a], log.note(size), sign_with=self.mitm))
        rcode, rout = self.rust(path, *self.tsa_args, *self.logkey_args)
        self.assertEqual(rcode, 1, rout)
        self.assertIn("log_signature", rout)
        pcode, pout = self.py(path, *self.tsa_args, *self.logkey_args)
        self.assertEqual(pcode, rcode, "the same command line: Rust FAILED, Python says:\n" + pout)

    # -- 5. Rust and Python disagree on the fixture bundle ------------------

    def fixture_bundle(self):
        with open(os.path.join(FIX, "bundle.json"), encoding="utf-8") as f:
            b = json.load(f)
        b["signature"] = None
        return b

    def fixture_args(self):
        t = os.path.join(FIX, "trust")
        return ["--tsa-roots", "a=" + os.path.join(t, "tsa-a-root.pem"),
                "--tsa-roots", "b=" + os.path.join(t, "tsa-b-root.pem")]

    def agree(self, name, text, expect=1):
        path = self.write(name, text)
        r, rout = self.rust(path, *self.fixture_args())
        p, pout = self.py(path, *self.fixture_args())
        self.assertEqual(r, p, f"Rust exit {r}, Python exit {p}\n--- rust\n{rout}\n--- python\n{pout}")
        self.assertEqual(r, expect, rout)

    def test_control_fixture_agrees(self):
        self.agree("fixture-unsigned.json", json.dumps(self.fixture_bundle(), ensure_ascii=False),
                   expect=0)

    def test_agree_negative_zero_in_record_fields(self):
        b = self.fixture_bundle()
        assert b["records"][9]["kind"] == "Fork" and b["records"][9]["fields"]["base"] == 0
        b["records"][9]["fields"]["base"] = "@NEG0@"
        self.agree("neg0.json", json.dumps(b, ensure_ascii=False).replace('"@NEG0@"', "-0"))

    def test_agree_impossible_generated_at(self):
        b = self.fixture_bundle()
        b["generated_at"] = "2026-02-30T25:61:61Z"
        self.agree("date.json", json.dumps(b, ensure_ascii=False))

    def test_agree_checkpoint_signature_name_with_plus(self):
        b = self.fixture_bundle()
        b["anchors"][0]["checkpoint"] += "\u2014 a+b AAAAAAE=\n"
        self.agree("plus.json", json.dumps(b, ensure_ascii=False))

    def test_agree_cosignature_line_with_embedded_lines(self):
        b = self.fixture_bundle()
        w = b["anchors"][0]["witnesses"][2]
        assert w["type"] == "cosignature"
        w["line"] = "\u2014 junk AAAAAAE=\n\n" + w["line"]
        self.agree("cosig-lines.json", json.dumps(b, ensure_ascii=False))

    def test_agree_ber_length_in_a_genuine_token(self):
        # The outer ContentInfo length is not covered by the TSA signature;
        # re-encoding it in non-minimal long form keeps OpenSSL happy.
        b = self.fixture_bundle()
        w = b["anchors"][0]["witnesses"][0]
        tok = base64.b64decode(w["token"])
        assert tok[:2] == b"\x30\x82"
        w["token"] = b64(b"\x30\x83\x00" + tok[2:])
        self.agree("ber.json", json.dumps(b, ensure_ascii=False))

    # -- 5b. a symlink shipped next to the bundle is followed on render ------

    def test_attack_planted_symlink_next_to_the_bundle(self):
        inbox = os.path.join(self.work, "inbox")
        os.makedirs(inbox, exist_ok=True)
        victim = self.write("victim.txt", "the auditor's own file\n")
        shutil.copy(os.path.join(FIX, "bundle.json"), os.path.join(inbox, "x.evidence.json"))
        link = os.path.join(inbox, "x.evidence.csv")
        if os.path.lexists(link):
            os.remove(link)
        os.symlink(victim, link)
        subprocess.run([PRAGMATIC, "render-evidence", os.path.join(inbox, "x.evidence.json"),
                        "--format", "csv"], capture_output=True)
        with open(victim) as f:
            self.assertEqual(f.read(), "the auditor's own file\n",
                             "render-evidence wrote through a symlink that came with the bundle")

    # -- 6. a pinned log key does not protect the bundle's own fields -------

    def test_attack_stripped_signature_with_pinned_log_key(self):
        b = self.fixture_bundle()  # genuine anchors, signature stripped
        b["requested_by"] = "tok_regulator_FCA"
        b["verification_spec"]["url"] = "https://evil.example/evidence-format.md"
        b["redaction"]["mode"] = "none"
        t = os.path.join(FIX, "trust")
        with open(os.path.join(t, "log.vkey")) as f:
            log_vkey = f.read().strip()
        path = self.write("stripped.json", b)
        code, out = self.rust(path, *self.fixture_args(), "--log-key", log_vkey)
        self.assertNotEqual(code, 0, "--log-key pinned, bundle signature missing, edited "
                            "fields printed, yet VERIFIED:\n" + out)
        self.assertIn("bundle_signature", out)
        self.assertIn("url, an unverified claim: https://evil.example", out)
        pcode, pout = self.py(path, *self.fixture_args(), "--log-key", log_vkey)
        self.assertEqual(pcode, 1, pout)
        self.assertIn("bundle_signature", pout)


if __name__ == "__main__":
    unittest.main()
