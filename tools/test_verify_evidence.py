#!/usr/bin/env python3
"""Tests for the reference evidence verifier, against the fixtures in
crates/pragmatic/tests/fixtures/evidence (see its README).

    python3 -m unittest tools/test_verify_evidence.py

Tests that need openssl skip, saying so, when it is not on PATH. Every
adversarial case of design section 9 that does not need Ed25519 fails here
with the same code as in `pragmatic verify-evidence`.
"""

import base64
import copy
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verify_evidence as ve  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "..", "crates", "pragmatic", "tests", "fixtures", "evidence")
HAVE_OPENSSL = shutil.which(ve.OPENSSL) is not None
needs_openssl = unittest.skipUnless(HAVE_OPENSSL, "openssl is not on PATH")


def fixture(name):
    return os.path.join(FIXTURES, name)


def load(name):
    with open(fixture(name), "rb") as f:
        return json.loads(f.read())


def roots(*which):
    return [(f"fixture-tsa-{x}", fixture(f"trust/tsa-{x}-root.pem")) for x in which]


def verify(bundle, tsa=("a", "b"), min_operators=2, log=None, witness_logs=()):
    data = bundle if isinstance(bundle, bytes) else json.dumps(bundle, ensure_ascii=False).encode()
    return ve.Verifier(roots(*tsa), min_operators, log, witness_logs).run(data)


def codes(report):
    return {f["code"] for f in report["findings"]}


def frames(journal):
    """(offset, end) of every frame of a journal file."""
    out, pos = [], 16
    while pos < len(journal):
        n = int.from_bytes(journal[pos:pos + 4], "little")
        out.append((pos, pos + 4 + n + 32))
        pos += 4 + n + 32
    return out


class Fixtures(unittest.TestCase):
    def assertFails(self, report, code):
        self.assertEqual(report["verdict"], "FAILED", report["findings"])
        self.assertEqual(report["exit"], 1)
        self.assertIn(code, codes(report))

    @needs_openssl
    def test_full_bundle_verifies(self):
        log = ve.load_log(fixture("log.json"))
        wl = ve.load_witness_log(fixture("witness-log.json"))
        r = verify(load("bundle.json"), log=log, witness_logs=[wl])
        self.assertEqual(r["verdict"], "VERIFIED", r["findings"])
        self.assertEqual(r["exit"], 0)
        self.assertEqual([a["entries"] for a in r["anchors"]], [6, 20, 32])
        for a in r["anchors"]:
            self.assertEqual(a["trusted_operators"], ["fixture-tsa-a", "fixture-tsa-b"])
            classes = [w["class"] for w in a["witnesses"]]
            self.assertEqual(classes, ["operator-controlled", "trusted", "trusted", "self-asserted"])
        self.assertIn("not_checked", codes(r))

    @needs_openssl
    def test_hmac_bundle_verifies(self):
        r = verify(load("bundle-hmac.json"))
        self.assertEqual(r["verdict"], "VERIFIED", r["findings"])
        b = load("bundle-hmac.json")
        b["anchor_id"] = None
        self.assertFails(verify(b), "run_id_mismatch")

    def test_local_bundle_is_unanchored(self):
        r = verify(load("local.json"))
        self.assertEqual(r["verdict"], "UNANCHORED", r["findings"])
        self.assertEqual(r["exit"], 3)
        self.assertIn("no_anchors", codes(r))
        self.assertIn("unsigned", codes(r))

    @needs_openssl
    def test_unpinned_roots(self):
        r = verify(load("bundle.json"), tsa=())
        self.assertEqual(r["verdict"], "UNANCHORED")
        self.assertIn("tsa_untrusted", codes(r))
        # One root pinned under both names: the other TSA's tokens fail.
        b_root = fixture("trust/tsa-b-root.pem")
        v = ve.Verifier([("a", b_root), ("b", b_root)], 2)
        r = v.run(ve.read_file(fixture("bundle.json")))
        self.assertEqual(r["verdict"], "UNANCHORED")
        self.assertIn("tsa_untrusted", codes(r))

    def test_cosignatures_never_count_here(self):
        r = verify(load("bundle.json"), tsa=(), min_operators=1)
        self.assertEqual(r["verdict"], "UNANCHORED")

    def test_without_openssl_tokens_are_unchecked(self):
        saved = ve.OPENSSL
        ve.OPENSSL = "/nonexistent/openssl"
        try:
            r = verify(load("bundle.json"))
        finally:
            ve.OPENSSL = saved
        self.assertEqual(r["verdict"], "UNANCHORED")
        self.assertIn("tsa_unchecked", codes(r))


class Adversarial(Fixtures):
    """Design section 9, and every other failure code reachable without
    Ed25519."""

    @needs_openssl
    def test_self_signed_tsa(self):
        rogue = load("rogue.json")
        b = load("bundle.json")
        for a in b["anchors"]:
            for w in a["witnesses"]:
                if w["type"] == "rfc3161":
                    w["token"] = rogue["tokens"][str(a["seq"])]
                    w["certs_pem"] = rogue["certs_pem"]
        r = verify(b)
        self.assertEqual(r["verdict"], "UNANCHORED", r["findings"])
        self.assertIn("tsa_untrusted", codes(r))

    @needs_openssl
    def test_omitted_anchor_caught_with_log(self):
        b = load("bundle.json")
        b["anchors"].pop()
        r = verify(b)
        self.assertEqual(r["verdict"], "VERIFIED (PARTIAL)", r["findings"])
        self.assertEqual(r["exit"], 2)
        self.assertFails(verify(b, log=ve.load_log(fixture("log.json"))), "anchor_omitted")
        b = load("bundle.json")
        del b["anchors"][1]
        self.assertFails(verify(b), "anchor_chain")

    def test_entries_and_head_mismatch(self):
        b = load("bundle.json")
        b["journal"]["entries"] += 1
        self.assertFails(verify(b), "entries_mismatch")
        b = load("bundle.json")
        h = bytearray(bytes.fromhex(b["journal"]["head"]))
        h[0] ^= 1
        b["journal"]["head"] = h.hex()
        self.assertFails(verify(b), "head_mismatch")

    def test_erased_slot_with_no_note(self):
        b = load("local.json")
        journal = base64.b64decode(b["journal"]["data"])
        last = frames(journal)[-1]
        journal = journal[:last[0]]
        b["journal"]["data"] = base64.b64encode(journal).decode()
        b["journal"]["entries"] -= 1
        b["journal"]["head"] = journal[-32:].hex()
        b["records"].pop()
        self.assertFails(verify(b), "unaccounted_erasure")

    def test_withheld_set_mismatch(self):
        b = load("bundle.json")
        b["redacted_slots"] = []
        self.assertFails(verify(b), "withheld_mismatch")

    def test_altered_records(self):
        b = load("bundle.json")
        b["records"][4]["slots"][2]["text"] = "Classify the ticket as resolved."
        self.assertFails(verify(b), "records_mismatch")

    def test_trailing_journal_bytes(self):
        b = load("bundle.json")
        journal = base64.b64decode(b["journal"]["data"]) + b"\x00\x00\x00"
        b["journal"]["data"] = base64.b64encode(journal).decode()
        self.assertFails(verify(b), "journal_trailing_bytes")

    def test_corrupt_journal(self):
        b = load("bundle.json")
        journal = bytearray(base64.b64decode(b["journal"]["data"]))
        start, end = frames(bytes(journal))[4]
        journal[end - 40] ^= 0x01
        b["journal"]["data"] = base64.b64encode(bytes(journal)).decode()
        self.assertFails(verify(b), "journal_parse")

    def test_duplicate_keys_and_strict_json(self):
        text = ve.read_file(fixture("bundle.json"))
        dup = text.replace(b'"generator":', b'"generator": "x", "generator":', 1)
        self.assertFails(verify(dup), "bundle_json")
        self.assertFails(verify(text + b"x"), "bundle_json")
        self.assertFails(verify(b"\xef\xbb\xbf" + text), "bundle_json")
        self.assertFails(verify(b'{"a": NaN}'), "bundle_json")
        self.assertFails(verify(b'["\\ud800"]'), "bundle_json")
        self.assertFails(verify(b"[" * 65 + b"]" * 65), "bundle_json")
        self.assertFails(verify(b"[" * 64 + b"]" * 64), "bundle_schema")
        self.assertFails(verify(text.replace(b'"seq": 0', b'"seq": 0.0', 1)), "bundle_schema")
        self.assertFails(verify(text.replace(b"{", b'{"extra": 1,', 1)), "bundle_schema")
        at = text.index(b'"anchor_digest": "') + len(b'"anchor_digest": "')
        upper = text[:at] + text[at:at + 64].upper() + text[at + 64:]
        self.assertNotEqual(upper, text)
        self.assertFails(verify(upper), "bundle_schema")

    def test_anchor_proofs(self):
        b = load("bundle.json")
        p = bytearray(bytes.fromhex(b["anchors"][0]["inclusion_proof"][0]))
        p[0] ^= 1
        b["anchors"][0]["inclusion_proof"][0] = p.hex()
        self.assertFails(verify(b, tsa=()), "anchor_inclusion")
        b = load("bundle.json")
        c = bytearray(bytes.fromhex(b["anchors"][0]["consistency_to_latest"][0]))
        c[0] ^= 1
        b["anchors"][0]["consistency_to_latest"][0] = c.hex()
        self.assertFails(verify(b, tsa=()), "anchor_consistency")
        b = load("bundle.json")
        b["anchors"][0]["tree_size"] += 1
        self.assertFails(verify(b, tsa=()), "anchor_checkpoint")
        b = load("bundle.json")
        d = bytearray(bytes.fromhex(b["anchors"][1]["anchor_digest"]))
        d[0] ^= 1
        b["anchors"][1]["anchor_digest"] = d.hex()
        r = verify(b, tsa=())
        self.assertFails(r, "anchor_digest")
        self.assertIn("tsa_imprint_mismatch", codes(r))
        b = load("bundle.json")
        b["anchors"][0]["leaf"] += "00"
        self.assertFails(verify(b, tsa=()), "anchor_leaf")
        b = load("bundle.json")
        b["run_id"] = "another-run"
        self.assertFails(verify(b, tsa=()), "run_id_mismatch")

    def test_witness_logs(self):
        wl = ve.load_witness_log(fixture("witness-log.json"))
        forked = copy.deepcopy(wl)
        lines = forked["checkpoints"][0].split("\n")
        lines[2] = base64.b64encode(b"\x07" * 32).decode()
        forked["checkpoints"][0] = "\n".join(lines)
        self.assertFails(verify(load("bundle.json"), tsa=(), witness_logs=[forked]), "witness_log_fork")
        missing = copy.deepcopy(wl)
        del missing["checkpoints"][1]
        self.assertFails(verify(load("bundle.json"), tsa=(), witness_logs=[missing]),
                         "witness_log_mismatch")

    def test_log_mismatch(self):
        log = ve.load_log(fixture("log.json"))
        log[0] = log[0][:-1] + bytes([log[0][-1] ^ 1])
        self.assertFails(verify(load("bundle.json"), tsa=(), log=log), "log_mismatch")


class CommandLine(unittest.TestCase):
    def run_main(self, *args):
        out = io.StringIO()
        with redirect_stdout(out):
            code = ve.main(list(args))
        return code, out.getvalue()

    @needs_openssl
    def test_exit_codes_and_json(self):
        code, out = self.run_main(
            fixture("bundle.json"),
            "--tsa-roots", "fixture-tsa-a=" + fixture("trust/tsa-a-root.pem"),
            "--tsa-roots", "fixture-tsa-b=" + fixture("trust/tsa-b-root.pem"),
            "--log", fixture("log.json"), "--json")
        self.assertEqual(code, 0, out)
        self.assertEqual(json.loads(out)["verdict"], "VERIFIED")
        code, out = self.run_main(fixture("bundle.json"))
        self.assertEqual(code, 3)
        self.assertIn("UNANCHORED", out)

    def test_usage(self):
        code, _ = self.run_main(fixture("bundle.json"), "--min-operators", "0")
        self.assertEqual(code, 64)
        code, _ = self.run_main(fixture("bundle.json"), "--tsa-roots", "/nonexistent.pem")
        self.assertEqual(code, 64)

    def test_hostile_text_is_escaped(self):
        b = load("local.json")
        b["generator"] = "\x1b[2J"
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, "b.json")
            with open(path, "w") as f:
                json.dump(b, f)
            code, out = self.run_main(path)
        finally:
            shutil.rmtree(tmp)
        self.assertEqual(code, 3)
        self.assertNotIn("\x1b", out)

    def test_directory_bundles(self):
        b = load("local.json")
        journal = base64.b64decode(b["journal"]["data"])
        b["journal"] = {"encoding": "file", "path": "journal.pragmatic",
                        "sha256": hashlib.sha256(journal).hexdigest(),
                        "entries": b["journal"]["entries"], "head": b["journal"]["head"]}
        tmp = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmp, "evidence.json"), "w") as f:
                json.dump(b, f)
            with open(os.path.join(tmp, "journal.pragmatic"), "wb") as f:
                f.write(journal)
            code, out = self.run_main(tmp)
            self.assertEqual(code, 3, out)
            with open(os.path.join(tmp, "journal.pragmatic"), "ab") as f:
                f.write(b"x")
            code, out = self.run_main(tmp)
            self.assertEqual(code, 1, out)
            self.assertIn("journal_missing", out)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
