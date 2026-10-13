#!/usr/bin/env python3
"""Reference verifier for Pragmatic evidence bundles (pragmatic-evidence/1).

    python3 verify_evidence.py BUNDLE [--tsa-roots [OPERATOR=]PEM]...
        [--min-operators N] [--log FILE] [--witness-log FILE]... [--json]

An independent implementation of the checks in docs/evidence-format.md,
using only the Python standard library and the `openssl` command (for RFC
3161 time-stamp tokens). It reimplements journal format 2 parsing from the
specification rather than calling Pragmatic, so a bundle that passes both
this and `pragmatic verify-evidence` has been checked by two programs that
share no code.

The Python standard library has no Ed25519, so this verifier does not check
the bundle signature, the log's checkpoint signatures or witness
cosignatures. It reports each of them as "not checked by the reference
verifier, use pragmatic verify-evidence", never counts a cosignature
towards independence, and so reaches VERIFIED only through RFC 3161
time-stamps from distinct operators.

Checks it cannot perform are reported with the code `not_checked`
(severity info). `--witness-key` and `--log-key` are accepted, so the same
command line works with both verifiers, and reported as not checked.

Exit codes: 0 VERIFIED, 2 VERIFIED (PARTIAL), 3 UNANCHORED, 1 FAILED,
64 usage error.
"""

import argparse
import base64
import calendar
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

FORMAT = "pragmatic-evidence/1"
NOT_CHECKED = "not checked by the reference verifier, use pragmatic verify-evidence"

FAILURE, WARNING, INFO = "failure", "warning", "info"
SEVERITY = {
    "bundle_json": FAILURE, "bundle_schema": FAILURE, "bundle_signature": FAILURE,
    "journal_missing": FAILURE, "journal_parse": FAILURE, "journal_format": FAILURE,
    "journal_trailing_bytes": FAILURE, "entries_mismatch": FAILURE, "head_mismatch": FAILURE,
    "chain": FAILURE, "withheld_mismatch": FAILURE, "unaccounted_erasure": FAILURE,
    "erasure_incomplete": FAILURE, "invalid_erasure_note": FAILURE,
    "records_mismatch": FAILURE, "run_id_mismatch": FAILURE, "anchor_leaf": FAILURE,
    "anchor_head_mismatch": FAILURE, "anchor_inclusion": FAILURE,
    "anchor_checkpoint": FAILURE, "anchor_digest": FAILURE, "anchor_consistency": FAILURE,
    "anchor_chain": FAILURE, "log_signature": FAILURE, "witness_malformed": FAILURE,
    "tsa_imprint_mismatch": FAILURE, "cosignature_invalid": FAILURE,
    "anchor_omitted": FAILURE, "log_mismatch": FAILURE, "witness_log_fork": FAILURE,
    "witness_log_mismatch": FAILURE,
    "tsa_untrusted": WARNING, "tsa_unchecked": WARNING, "cosignature_untrusted": WARNING,
    "witness_key_expired": WARNING, "operator_mismatch": WARNING, "log_newer": WARNING,
    "witness_log_origin": WARNING,
    "unsigned": INFO, "operator_asserted": INFO, "no_anchors": INFO, "not_checked": INFO,
}
ALIASES = {"entrust": "sectigo", "quovadis-eu": "digicert"}
OPENSSL = os.environ.get("OPENSSL", "openssl")


class Invalid(Exception):
    """A bundle that cannot be read: (code, message)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def sha256(data):
    return hashlib.sha256(data).digest()


# -- strict JSON (design 3.7) ----------------------------------------------------


class Int(int):
    """An integer that remembers how it was written."""

    text = ""


def _int(text):
    v = Int(int(text))
    v.text = text
    return v


def _float(text):
    return ("float", text)


def _no_duplicates(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise ValueError("duplicate object key " + repr(k))
        seen[k] = v
    return seen


def _no_constant(name):
    raise ValueError("not JSON: " + name)


def _check_tree(value, depth=0):
    """Lone surrogates and nesting: a top-level array or object is depth 1,
    and 64 is the deepest allowed."""
    if isinstance(value, str):
        value.encode("utf-8")  # raises on a lone surrogate
        return
    if not isinstance(value, (dict, list)):
        return
    depth += 1
    if depth > 64:
        raise ValueError("nested deeper than 64")
    if isinstance(value, dict):
        for k, v in value.items():
            k.encode("utf-8")
            _check_tree(v, depth)
    else:
        for v in value:
            _check_tree(v, depth)


def strict_json(data):
    """Parse strict JSON, raising Invalid("bundle_json") on any departure."""
    if data.startswith(b"\xef\xbb\xbf"):
        raise Invalid("bundle_json", "byte-order mark")
    try:
        text = data.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_int=_int,
                           parse_float=_float, parse_constant=_no_constant)
        _check_tree(value)
    except (UnicodeError, ValueError, RecursionError) as e:
        raise Invalid("bundle_json", f"not strict JSON: {e}")
    return value


def canonical(value):
    def plain(v):
        if isinstance(v, tuple):
            raise ValueError("a fraction where only integers appear")
        if isinstance(v, dict):
            return {k: plain(x) for k, x in v.items()}
        if isinstance(v, list):
            return [plain(x) for x in v]
        if isinstance(v, Int):
            return int(v)
        return v
    return json.dumps(plain(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# -- schema ------------------------------------------------------------------------

HEX = re.compile(r"[0-9a-f]*")
UINT = re.compile(r"0|[1-9][0-9]*")


def obj(value, at, keys):
    if not isinstance(value, dict):
        raise Invalid("bundle_schema", f"{at} is not an object")
    for k in value:
        if k not in keys:
            raise Invalid("bundle_schema", f"{at} has an unknown key {k!r}")
    for k in keys:
        if k not in value:
            raise Invalid("bundle_schema", f"{at} is missing the key {k!r}")
    return value


def string(v, at, nullable=False):
    if v is None and nullable:
        return None
    if not isinstance(v, str):
        raise Invalid("bundle_schema", f"{at} is not a string")
    return v


def uint(v, at, bits=64):
    if not isinstance(v, Int) or not UINT.fullmatch(v.text) or v >= 2**bits:
        raise Invalid("bundle_schema", f"{at} is not an integer of at most {bits} bits")
    return int(v)


def hexbytes(v, at, length=None):
    s = string(v, at)
    if not HEX.fullmatch(s) or len(s) % 2 or (length is not None and len(s) != 2 * length):
        raise Invalid("bundle_schema", f"{at} is not lowercase hex" +
                      (f" of {length} bytes" if length else ""))
    return bytes.fromhex(s)


def b64bytes(v, at):
    s = string(v, at)
    try:
        raw = base64.b64decode(s, validate=True)
    except ValueError:
        raise Invalid("bundle_schema", f"{at} is not base64")
    if base64.b64encode(raw).decode() != s:
        raise Invalid("bundle_schema", f"{at} is not canonical base64")
    return raw


def array(v, at):
    if not isinstance(v, list):
        raise Invalid("bundle_schema", f"{at} is not an array")
    return v


def pair(v, at):
    if not isinstance(v, list) or len(v) != 2:
        raise Invalid("bundle_schema", f"{at} is not [cursor, slot]")
    return (uint(v[0], at), uint(v[1], at, 8))


RFC3339 = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,9})?Z")
BUNDLE_KEYS = ["anchor_id", "anchors", "format", "generated_at", "generator", "independent",
               "journal", "latest_checkpoint", "records", "redacted_slots", "redaction",
               "requested_by", "run_id", "signature", "verification_spec"]


def read_bundle(value):
    """Check the bundle's shape (section 3) and return it with bytes decoded."""
    b = obj(value, "bundle", BUNDLE_KEYS)
    if b["format"] != FORMAT:
        raise Invalid("bundle_schema", f"bundle.format is not {FORMAT!r}")
    if not RFC3339.fullmatch(string(b["generated_at"], "bundle.generated_at")):
        raise Invalid("bundle_schema", "bundle.generated_at is not an RFC 3339 UTC time")
    for k in ("generator", "requested_by", "run_id"):
        string(b[k], "bundle." + k)
    if not isinstance(b["independent"], bool):
        raise Invalid("bundle_schema", "bundle.independent is not a boolean")
    out = {"run_id": b["run_id"], "raw": b}
    out["anchor_id"] = None if b["anchor_id"] is None else hexbytes(b["anchor_id"], "bundle.anchor_id", 32)
    j = b["journal"]
    if not isinstance(j, dict) or j.get("encoding") not in ("base64", "file"):
        raise Invalid("bundle_schema", "bundle.journal.encoding is neither base64 nor file")
    if j["encoding"] == "base64":
        obj(j, "bundle.journal", ["data", "encoding", "entries", "head"])
        out["journal"] = b64bytes(j["data"], "bundle.journal.data")
        out["journal_file"] = None
    else:
        obj(j, "bundle.journal", ["encoding", "entries", "head", "path", "sha256"])
        path = string(j["path"], "bundle.journal.path")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,255}", path) or path in (".", ".."):
            raise Invalid("bundle_schema", "bundle.journal.path is not a plain file name")
        out["journal"] = None
        out["journal_file"] = (path, hexbytes(j["sha256"], "bundle.journal.sha256", 32))
    out["entries"] = uint(j["entries"], "bundle.journal.entries")
    out["head"] = hexbytes(j["head"], "bundle.journal.head", 32)
    r = obj(b["redaction"], "bundle.redaction", ["detectors", "mode", "patterns_sha256"])
    if r["mode"] not in ("none", "detectors", "binary", "all"):
        raise Invalid("bundle_schema", "bundle.redaction.mode is not a known mode")
    for i, d in enumerate(array(r["detectors"], "bundle.redaction.detectors")):
        string(d, f"bundle.redaction.detectors[{i}]")
    hexbytes(r["patterns_sha256"], "bundle.redaction.patterns_sha256", 32)
    out["redacted_slots"] = [pair(p, f"bundle.redacted_slots[{i}]")
                             for i, p in enumerate(array(b["redacted_slots"], "bundle.redacted_slots"))]
    for i, rec in enumerate(array(b["records"], "bundle.records")):
        read_record(rec, f"bundle.records[{i}]")
    out["records"] = b["records"]
    out["anchors"] = [read_anchor(a, f"bundle.anchors[{i}]")
                      for i, a in enumerate(array(b["anchors"], "bundle.anchors"))]
    out["latest_checkpoint"] = string(b["latest_checkpoint"], "bundle.latest_checkpoint", True)
    if b["verification_spec"] is not None:
        s = obj(b["verification_spec"], "bundle.verification_spec", ["sha256", "url"])
        string(s["url"], "bundle.verification_spec.url")
        hexbytes(s["sha256"], "bundle.verification_spec.sha256", 32)
    if b["signature"] is not None:
        s = obj(b["signature"], "bundle.signature", ["key_id", "public_key", "value"])
        hexbytes(s["key_id"], "bundle.signature.key_id", 4)
        hexbytes(s["public_key"], "bundle.signature.public_key", 32)
        hexbytes(s["value"], "bundle.signature.value", 64)
    out["signature"] = b["signature"]
    return out


def read_record(rec, at):
    obj(rec, at, ["at", "branch", "cursor", "fields", "hash", "kind", "slots"])
    uint(rec["cursor"], at + ".cursor")
    uint(rec["at"], at + ".at")
    for i, x in enumerate(array(rec["branch"], at + ".branch")):
        uint(x, f"{at}.branch[{i}]", 32)
    string(rec["kind"], at + ".kind")
    if not isinstance(rec["fields"], dict):
        raise Invalid("bundle_schema", at + ".fields is not an object")
    hexbytes(rec["hash"], at + ".hash", 32)
    for i, s in enumerate(array(rec["slots"], at + ".slots")):
        sat = f"{at}.slots[{i}]"
        obj(s, sat, ["base64", "commitment", "len", "ref", "state", "text"])
        if s["state"] not in ("sealed", "erased", "withheld", "ref"):
            raise Invalid("bundle_schema", sat + ".state is not a known state")
        hexbytes(s["commitment"], sat + ".commitment", 32)
        if s["len"] is not None:
            uint(s["len"], sat + ".len")
        string(s["text"], sat + ".text", True)
        if s["base64"] is not None:
            b64bytes(s["base64"], sat + ".base64")
        if s["ref"] is not None:
            pair(s["ref"], sat + ".ref")


def read_anchor(a, at):
    obj(a, at, ["anchor_digest", "checkpoint", "consistency_to_latest", "inclusion_proof",
                "leaf", "leaf_index", "root", "seq", "tree_size", "witnesses"])
    out = {
        "seq": uint(a["seq"], at + ".seq"),
        "tree_size": uint(a["tree_size"], at + ".tree_size"),
        "leaf_index": uint(a["leaf_index"], at + ".leaf_index"),
        "leaf": hexbytes(a["leaf"], at + ".leaf"),
        "inclusion_proof": [hexbytes(h, f"{at}.inclusion_proof[{i}]", 32)
                            for i, h in enumerate(array(a["inclusion_proof"], at + ".inclusion_proof"))],
        "root": hexbytes(a["root"], at + ".root", 32),
        "checkpoint": string(a["checkpoint"], at + ".checkpoint"),
        "anchor_digest": hexbytes(a["anchor_digest"], at + ".anchor_digest", 32),
        "consistency": [hexbytes(h, f"{at}.consistency_to_latest[{i}]", 32)
                        for i, h in enumerate(array(a["consistency_to_latest"], at + ".consistency_to_latest"))],
        "witnesses": [],
    }
    for i, w in enumerate(array(a["witnesses"], at + ".witnesses")):
        wat = f"{at}.witnesses[{i}]"
        kind = w.get("type") if isinstance(w, dict) else None
        if kind == "rfc3161":
            obj(w, wat, ["certs_pem", "operator", "token", "tsa", "type"])
            out["witnesses"].append({
                "type": kind, "tsa": string(w["tsa"], wat + ".tsa"),
                "operator": string(w["operator"], wat + ".operator"),
                "token": b64bytes(w["token"], wat + ".token"),
                "certs_pem": string(w["certs_pem"], wat + ".certs_pem")})
        elif kind == "cosignature":
            obj(w, wat, ["line", "name", "type"])
            out["witnesses"].append({"type": kind, "name": string(w["name"], wat + ".name"),
                                     "line": string(w["line"], wat + ".line")})
        else:
            raise Invalid("bundle_schema", wat + ".type is not rfc3161 or cosignature")
    return out


# -- journal format 2 (sections 2.2 to 2.5 of the design) ------------------------

KINDS = {
    1: ("DrawIntent", ["provenance"], ["str"], 1, 255),
    2: ("DrawResult", ["intent", "meta"], ["u64", "json"], 2, 2),
    3: ("ChannelRecv", ["channel"], ["str"], 1, 1),
    4: ("EffectIntent", ["name"], ["str"], 1, 1),
    5: ("EffectResult", ["intent", "outcome", "error_kind"], ["u64", "outcome", "str"], 0, 1),
    6: ("Clock", ["nanos"], ["u64"], 0, 0),
    7: ("Program", ["name", "hash"], ["str", "str"], 0, 0),
    8: ("Fork", ["base", "children"], ["u32", "u32"], 0, 0),
    9: ("Marker", ["name"], ["str"], 0, 0),
    10: ("Note", ["kind", "data"], ["str", "json"], 0, 2),
    11: ("Random", ["source", "args"], ["str", "json"], 1, 1),
    12: ("Refusal", ["step", "name", "fault"], ["str", "str", "str"], 0, 0),
}
STATES = {1: "sealed", 2: "erased", 3: "withheld", 4: "ref"}
META = [0xFFFFFFFF]
MAX_SLOT = 64 << 20
MAX_RECORD = 256 << 20


class Corrupt(Exception):
    pass


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        if n > len(self.data) - self.pos:
            raise Corrupt("record ends early")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self):
        return self.take(1)[0]

    def u32(self):
        return int.from_bytes(self.take(4), "little")

    def u64(self):
        return int.from_bytes(self.take(8), "little")


def strict_field_json(raw):
    try:
        strict_json(raw)
    except Invalid:
        raise Corrupt("JSON field is not strict JSON")


def decode_record(rec, cursor, prior):
    """Decode one record canonically (design 2.4); return the entry."""
    r = Reader(rec)
    kind = r.u8()
    if kind not in KINDS:
        raise Corrupt("unknown record kind")
    name, names, types, lo, hi = KINDS[kind]
    at = r.u64()
    depth = r.u8()
    if depth > 32:
        raise Corrupt("branch deeper than 32")
    branch = [r.u32() for _ in range(depth)]
    if r.u8() != len(types):
        raise Corrupt("field count does not match the kind")
    fields, raw_fields = {}, []
    for fname, ty in zip(names, types):
        raw = r.take(r.u32())
        raw_fields.append(raw)
        if ty in ("u64", "u32"):
            if len(raw) != (8 if ty == "u64" else 4):
                raise Corrupt("integer field has the wrong width")
            fields[fname] = int.from_bytes(raw, "little")
        else:
            try:
                text = raw.decode("utf-8")
            except UnicodeError:
                raise Corrupt("text field is not UTF-8")
            if ty == "json":
                strict_field_json(raw)
            if ty == "outcome" and text not in ("ok", "failed", "compensated"):
                raise Corrupt("unknown effect outcome")
            fields[fname] = text
    nslots = r.u8()
    if kind == 5:
        lo = hi = 0 if fields["outcome"] == "compensated" else 1
    if not lo <= nslots <= hi:
        raise Corrupt("slot count does not match the kind")
    slots = []
    for _ in range(nslots):
        state = r.u8()
        commitment = r.take(32)
        slot = {"state": STATES.get(state), "commitment": commitment, "content": None,
                "salt": None, "ref": None}
        if state == 1:
            salt = r.take(16)
            n = r.u32()
            if n > MAX_SLOT:
                raise Corrupt("slot exceeds the 64 MiB limit")
            slot["salt"], slot["content"] = salt, r.take(n)
        elif state == 4:
            tc, ts = r.u64(), r.u8()
            if tc >= cursor or tc >= len(prior):
                raise Corrupt("ref does not point to an earlier entry")
            target_slots = prior[tc]["slots"]
            if ts >= len(target_slots):
                raise Corrupt("ref target slot does not exist")
            target = target_slots[ts]
            if target["state"] not in ("sealed", "erased", "withheld"):
                raise Corrupt("ref points to another ref")
            if target["commitment"] != commitment:
                raise Corrupt("ref commitment differs from its target")
            slot["ref"] = (tc, ts)
            slot["content"] = target["content"]
        elif state not in (2, 3):
            raise Corrupt("unknown slot state")
        slots.append(slot)
    if r.pos != len(rec):
        raise Corrupt("trailing bytes in record")
    if (branch == META) != (kind == 10):
        raise Corrupt("only notes may be on the meta branch, and notes must be")
    if kind == 8 and fields["children"] == 0:
        raise Corrupt("fork has no children")
    if kind == 12:
        step, nm, fault = fields["step"], fields["name"], fields["fault"]
        fits = {"draw": fault == "BudgetExhausted" and nm == "",
                "recv": fault == "Timeout", "effect": fault == "CapabilityDenied"}
        if not fits.get(step, False):
            raise Corrupt("refusal fault or name does not fit its step")
    if kind in (2, 5):
        intent = fields["intent"]
        want = "DrawIntent" if kind == 2 else "EffectIntent"
        if intent >= cursor or prior[intent]["kind"] != want or prior[intent]["branch"] != branch:
            raise Corrupt("result does not complete an earlier intent of its kind on its branch")
    entry = {"cursor": cursor, "at": at, "branch": branch, "kind": name, "tag": kind,
             "fields": fields, "raw_fields": raw_fields, "slots": slots}
    if encode_record(entry) != rec:
        raise Corrupt("record is not canonically encoded")
    return entry


def encode_head(e):
    out = bytes([e["tag"]]) + e["at"].to_bytes(8, "little") + bytes([len(e["branch"])])
    out += b"".join(x.to_bytes(4, "little") for x in e["branch"])
    out += bytes([len(e["raw_fields"])])
    out += b"".join(len(f).to_bytes(4, "little") + f for f in e["raw_fields"])
    return out


def encode_record(e):
    out = encode_head(e) + bytes([len(e["slots"])])
    for s in e["slots"]:
        state = {v: k for k, v in STATES.items()}[s["state"]]
        out += bytes([state]) + s["commitment"]
        if s["state"] == "sealed":
            out += s["salt"] + len(s["content"]).to_bytes(4, "little") + s["content"]
        elif s["state"] == "ref":
            out += s["ref"][0].to_bytes(8, "little") + bytes([s["ref"][1]])
    return out


def skeleton(e):
    return (encode_head(e) + bytes([len(e["slots"])])
            + b"".join(b"\x01" + s["commitment"] for s in e["slots"]))


def commitment(salt, content):
    return sha256(b"pragmatic/v2/slot" + salt + len(content).to_bytes(8, "little") + content)


def parse_journal(data):
    """Return (entries, heads) where heads[n] is the head after n entries."""
    if len(data) < 12 or data[:8] != b"PRAGJRNL":
        raise Invalid("journal_parse", "not a Pragmatic journal (bad magic)")
    version = int.from_bytes(data[8:12], "little")
    if version == 1:
        raise Invalid("journal_format", "evidence journals are format 2; this one is format 1")
    if version != 2 or len(data) < 16:
        raise Invalid("journal_parse", f"unsupported journal format {version}")
    flags = int.from_bytes(data[12:16], "little")
    if flags != 0:
        raise Invalid("journal_parse", "the journal is keyed or has reserved flags set")
    heads = [sha256(b"pragmatic/v2/genesis" + flags.to_bytes(4, "little"))]
    entries, pos = [], 16
    while pos < len(data):
        if len(data) - pos < 4:
            raise Invalid("journal_trailing_bytes", f"{len(data) - pos} bytes follow the last complete entry")
        n = int.from_bytes(data[pos:pos + 4], "little")
        end = pos + 4 + n + 32
        if n > MAX_RECORD or end > len(data):
            raise Invalid("journal_trailing_bytes", f"{len(data) - pos} bytes follow the last complete entry")
        rec, stored = data[pos + 4:pos + 4 + n], data[end - 32:end]
        cursor = len(entries)
        try:
            e = decode_record(rec, cursor, entries)
        except Corrupt as why:
            raise Invalid("journal_parse", f"journal corrupt at cursor {cursor}: {why}")
        for s in e["slots"]:
            if s["state"] == "sealed" and commitment(s["salt"], s["content"]) != s["commitment"]:
                raise Invalid("journal_parse", f"journal corrupt at cursor {cursor}: slot content does not match its commitment")
        link = sha256(heads[-1] + cursor.to_bytes(8, "little") + skeleton(e))
        if link != stored:
            raise Invalid("journal_parse", f"journal corrupt at cursor {cursor}: chain link does not verify")
        e["hash"] = stored
        entries.append(e)
        heads.append(stored)
        pos = end
    return entries, heads


def record_of(e):
    fields = {}
    for name, ty in zip(KINDS[e["tag"]][1], KINDS[e["tag"]][2]):
        fields[name] = e["fields"][name]
    slots = []
    for s in e["slots"]:
        content = s["content"]
        text = b64 = length = None
        if content is not None:
            length = len(content)
            try:
                text = content.decode("utf-8")
            except UnicodeError:
                b64 = base64.b64encode(content).decode()
        slots.append({"state": s["state"], "commitment": s["commitment"].hex(), "len": length,
                      "text": text, "base64": b64,
                      "ref": list(s["ref"]) if s["ref"] else None})
    return {"cursor": e["cursor"], "at": e["at"], "branch": e["branch"], "kind": e["kind"],
            "fields": fields, "slots": slots, "hash": e["hash"].hex()}


# -- Merkle proofs (RFC 9162 2.1.3.2 and 2.1.4.2) --------------------------------


def leaf_hash(d):
    return sha256(b"\x00" + d)


def node_hash(l, r):
    return sha256(b"\x01" + l + r)


def mth(hashes):
    if not hashes:
        return sha256(b"")
    if len(hashes) == 1:
        return hashes[0]
    k = 1
    while k * 2 < len(hashes):
        k *= 2
    return node_hash(mth(hashes[:k]), mth(hashes[k:]))


def verify_inclusion(lh, index, size, proof, root):
    if index >= size:
        return False
    fn, sn, r = index, size - 1, lh
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(m, n, root_m, root_n, proof):
    if m > n:
        return False
    if m == 0:
        return not proof and root_m == sha256(b"") and (n > 0 or root_n == sha256(b""))
    if m == n:
        return not proof and root_m == root_n
    if not proof:
        return False
    if m & (m - 1) == 0:
        path = [root_m] + list(proof)
    else:
        path = list(proof)
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == root_m and sr == root_n


# -- leaves, notes, checkpoints ----------------------------------------------------

LEAF_TAG = b"pragmatic/v2/leaf"


def decode_leaf(d):
    if not d.startswith(LEAF_TAG):
        raise ValueError("leaf does not start with the pragmatic/v2/leaf tag")
    r = Reader(d[len(LEAF_TAG):])
    try:
        kind = r.u8()
        n = r.u32()
        if kind not in (0, 1) or n > 1024:
            raise ValueError("leaf type or id length is out of range")
        ident = r.take(n)
        entries = r.u64()
        head = r.take(32)
        prev = r.u64()
    except Corrupt:
        raise ValueError("leaf ends early")
    if r.pos != len(r.data):
        raise ValueError("leaf has trailing bytes")
    return {"kind": kind, "id": ident, "entries": entries, "head": head,
            "prev": None if prev == 2**64 - 1 else prev}


def parse_note(text):
    """Split a signed note into (body, [(name, key id, signature bytes)])."""
    if any(c < " " and c != "\n" for c in text):
        raise ValueError("control character in note")
    split = text.rfind("\n\n")
    if split < 0 or not text.endswith("\n"):
        raise ValueError("not a signed note")
    body, lines = text[:split + 1], text[split + 2:-1].split("\n")
    sigs = []
    for line in lines:
        if not line.startswith("\u2014 "):
            raise ValueError("signature line does not start with an em dash")
        name, _, b64 = line[2:].partition(" ")
        raw = base64.b64decode(b64, validate=True)
        if not name or base64.b64encode(raw).decode() != b64 or len(raw) < 5:
            raise ValueError("malformed signature line")
        sigs.append((name, raw[:4], raw[4:]))
    return body, sigs


def parse_checkpoint(body):
    if not body.endswith("\n"):
        raise ValueError("checkpoint does not end in a newline")
    lines = body[:-1].split("\n")
    if len(lines) < 3 or any(not l for l in lines):
        raise ValueError("checkpoint has fewer than three lines or an empty line")
    if not UINT.fullmatch(lines[1]) or int(lines[1]) >= 2**64:
        raise ValueError("tree size is not a canonical decimal")
    root = base64.b64decode(lines[2], validate=True)
    if len(root) != 32 or base64.b64encode(root).decode() != lines[2]:
        raise ValueError("root is not canonical base64 of 32 bytes")
    return {"origin": lines[0], "tree_size": int(lines[1]), "root": root}


# -- RFC 3161 tokens: DER walking and openssl -------------------------------------


def der(data, pos=0):
    """One TLV at pos: (tag, value, end)."""
    if pos + 2 > len(data):
        raise ValueError("DER ends early")
    tag, n = data[pos], data[pos + 1]
    pos += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or pos + k > len(data):
            raise ValueError("bad DER length")
        n = int.from_bytes(data[pos:pos + k], "big")
        pos += k
    if pos + n > len(data):
        raise ValueError("DER value exceeds its container")
    return tag, data[pos:pos + n], pos + n


def children(value):
    out, pos = [], 0
    while pos < len(value):
        tag, v, pos = der(value, pos)
        out.append((tag, v))
    return out


SHA256_OID = bytes.fromhex("608648016503040201")
SIGNED_DATA_OID = bytes.fromhex("2a864886f70d010702")
TST_INFO_OID = bytes.fromhex("2a864886f70d0109100104")


def single(value, tag):
    """The one TLV that fills `value`, which must have `tag`."""
    t, v, end = der(value)
    if t != tag or end != len(value):
        raise ValueError(f"expected one element with tag {tag:#x}")
    return v


def tst_info(token):
    """The fields of a token's TSTInfo this verifier needs: walk ContentInfo,
    SignedData, EncapsulatedContentInfo and the eContent OCTET STRING
    (RFC 3161 section 2.4.2, RFC 5652). Signatures are left to openssl."""
    ci = children(single(token, 0x30))
    if len(ci) != 2 or ci[0] != (0x06, SIGNED_DATA_OID) or ci[1][0] != 0xA0:
        raise ValueError("token is not a signedData ContentInfo")
    signed = children(single(ci[1][1], 0x30))
    if len(signed) < 4 or signed[2][0] != 0x30:
        raise ValueError("malformed SignedData")
    encap = children(signed[2][1])
    if len(encap) != 2 or encap[0] != (0x06, TST_INFO_OID) or encap[1][0] != 0xA0:
        raise ValueError("encapsulated content is not TSTInfo")
    tst = children(single(single(encap[1][1], 0x04), 0x30))
    if len(tst) < 5 or tst[2][0] != 0x30 or tst[4][0] != 0x18:
        raise ValueError("malformed TSTInfo")
    imprint = children(tst[2][1])
    algorithm = children(imprint[0][1])[0][1]
    hashed = imprint[1][1]
    accuracy = 0
    if len(tst) > 5 and tst[5][0] == 0x30:
        scale = {0x02: 10**9, 0x80: 10**6, 0x81: 10**3}
        for t, v in children(tst[5][1]):
            accuracy += int.from_bytes(v, "big") * scale.get(t, 0)
    gen = tst[4][1].decode("ascii")
    m = re.fullmatch(r"(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(?:\.(\d+))?Z", gen)
    if not m:
        raise ValueError("genTime is not GeneralizedTime in UTC")
    secs = calendar.timegm(tuple(int(x) for x in m.groups()[:6]) + (0, 0, 0))
    frac = int((m.group(7) or "0").ljust(9, "0")[:9])
    return {"sha256": algorithm == SHA256_OID, "hashed": hashed, "gen_unix": secs,
            "time_ns": secs * 10**9 + frac + accuracy}


def check_certs_pem(pem):
    body = None
    for line in pem.splitlines():
        if body is None:
            if line == "":
                continue
            if line != "-----BEGIN CERTIFICATE-----":
                return False
            body = ""
        elif line == "-----END CERTIFICATE-----":
            try:
                raw = base64.b64decode(body, validate=True)
            except ValueError:
                return False
            if not body or base64.b64encode(raw).decode() != body:
                return False
            body = None
        else:
            if not line or len(line) > 64:
                return False
            body += line
    return body is None


def openssl_verify(token, digest, certs_pem, root, at_time, index):
    """openssl ts -verify, exactly as section 8 step 9 says. Returns
    (verified, reason); reason is None when openssl is missing."""
    if shutil.which(OPENSSL) is None:
        return False, None
    hexdigest = digest.hex()
    if not re.fullmatch(r"[0-9a-f]{64}", hexdigest):
        return False, "digest is not 64 lowercase hex digits"
    work = tempfile.mkdtemp(prefix="pragmatic-tsa-")  # mode 0700
    try:
        tok = os.path.join(work, f"{index}.der")
        with open(tok, "wb") as f:
            f.write(token)
        args = [OPENSSL, "ts", "-verify", "-token_in", "-in", tok, "-digest", hexdigest,
                "-CAfile", os.path.abspath(root), "-attime", str(at_time)]
        if certs_pem.strip():
            pem = os.path.join(work, f"{index}.pem")
            with open(pem, "w") as f:
                f.write(certs_pem)
            args += ["-untrusted", pem]
        p = subprocess.run(args, capture_output=True, stdin=subprocess.DEVNULL)
        if p.returncode == 0 and b"Verification: OK" in p.stdout:
            return True, ""
        err = p.stderr.decode(errors="replace").strip().splitlines()
        reason = next((l for l in err if "rror" in l), err[0] if err else "openssl ts -verify failed")
        return False, reason.rsplit(":", 1)[-1].strip()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def normalize(name):
    return re.sub(r"[\s_]+", "-", name.strip()).lower()


def operator(name):
    n = normalize(name)
    return ALIASES.get(n, n)


# -- the procedure -------------------------------------------------------------------


class Verifier:
    def __init__(self, roots, min_operators, log=None, witness_logs=()):
        self.roots = roots  # [(operator, path)]
        self.min = min_operators
        self.log = log
        self.witness_logs = list(witness_logs)
        self.findings, self.checks, self.anchors = [], [], []
        self.entries = 0
        self.index = 0

    def find(self, code, message):
        self.findings.append({"code": code, "severity": SEVERITY[code], "message": message})

    def check(self, step, name, status, detail):
        self.checks.append({"step": step, "name": name, "status": status, "detail": detail})

    def failures(self):
        return [f for f in self.findings if f["severity"] == FAILURE]

    def run(self, data, directory=None):
        try:
            b = read_bundle(strict_json(data))
        except Invalid as e:
            self.find(e.code, e.message)
            self.check(1, "strict JSON, known keys", "fail", e.message)
            return self.result()
        self.run_id = b["run_id"]
        self.check(1, "strict JSON, known keys", "pass", "exactly the keys of " + FORMAT)
        if b["signature"] is None:
            self.find("unsigned", "the bundle is not signed")
        else:
            self.find("not_checked", "bundle signature: " + NOT_CHECKED)
        self.check(1, "bundle signature", "info", "unsigned" if b["signature"] is None else NOT_CHECKED)
        journal = b["journal"]
        if journal is None:
            path, digest = b["journal_file"]
            try:
                with open(os.path.join(directory or ".", path), "rb") as f:
                    journal = f.read()
            except OSError:
                journal = None
            if journal is None or sha256(journal) != digest:
                self.find("journal_missing", "the bundle's journal file is missing or does not match its sha256")
                return self.result()
        try:
            entries, heads = parse_journal(journal)
        except Invalid as e:
            self.find(e.code, e.message)
            self.check(2, "journal parses canonically", "fail", e.message)
            return self.result()
        self.entries = len(entries)
        ok = True
        if len(entries) != b["entries"]:
            ok = False
            self.find("entries_mismatch", f"the bundle states {b['entries']} entries; the journal has {len(entries)}")
        if heads[-1] != b["head"]:
            ok = False
            self.find("head_mismatch", "the bundle's head is not the journal's head")
        self.check(2, "journal parses canonically", "pass" if ok else "fail", f"{len(entries)} entries")
        self.check(3, "chain", "pass", "every link, commitment and ref verifies")
        self.withheld(b, entries)
        self.erasure(entries)
        self.records(b, entries)
        self.run_start(b, entries)
        latest = self.verify_anchors(b, heads)
        self.full_log(b, latest)
        for wl in self.witness_logs:
            self.witness_log(b, wl, latest)
        return self.result()

    def withheld(self, b, entries):
        actual = [(e["cursor"], k) for e in entries for k, s in enumerate(e["slots"]) if s["state"] == "withheld"]
        if b["redacted_slots"] != actual:
            self.find("withheld_mismatch", "redacted_slots does not equal the withheld slots")
            self.check(4, "withheld slots", "fail", "mismatch")
        else:
            self.check(4, "withheld slots", "pass", f"{len(actual)} withheld slot(s), all listed")

    def erasure(self, entries):
        listed = set()
        bad = False
        for e in entries:
            if e["kind"] != "Note" or e["fields"]["kind"] != "erasure":
                continue
            try:
                doc = json.loads(e["fields"]["data"])
                pairs = doc["slots"]
                assert isinstance(pairs, list)
            except Exception:
                self.find("invalid_erasure_note", f"the erasure note at cursor {e['cursor']} cannot be read")
                bad = True
                continue
            for p in pairs:
                ok = (isinstance(p, list) and len(p) == 2 and all(type(x) is int and x >= 0 for x in p)
                      and p[0] < e["cursor"] and p[1] < 256 and p[1] < len(entries[p[0]]["slots"]))
                if ok:
                    listed.add((p[0], p[1]))
                else:
                    self.find("invalid_erasure_note", f"the erasure note at cursor {e['cursor']} lists a slot that does not exist")
                    bad = True
        for c, k in sorted(listed):
            if entries[c]["slots"][k]["content"] is not None:
                self.find("erasure_incomplete", f"slot {c}:{k} is listed as erased but still holds content")
                bad = True
        erased = [(e["cursor"], k) for e in entries for k, s in enumerate(e["slots"]) if s["state"] == "erased"]
        missing = [x for x in erased if x not in listed]
        if missing:
            bad = True
            self.find("unaccounted_erasure", f"{len(missing)} erased slot(s) no later erasure note lists, first {missing[0][0]}:{missing[0][1]}")
        self.check(5, "erasures accounted for", "fail" if bad else "pass", f"{len(erased)} erased slot(s)")

    def records(self, b, entries):
        expected = [canonical(record_of(e)) for e in entries]
        given = [canonical(r) for r in b["records"]]
        if expected != given:
            self.find("records_mismatch", "records differ from the decoded journal")
            self.check(6, "records equal the journal", "fail", "mismatch")
        else:
            self.check(6, "records equal the journal", "pass", f"{len(given)} records")

    def run_start(self, b, entries):
        rid = None
        if entries and entries[0]["kind"] == "Note" and entries[0]["fields"]["kind"] == "run.start":
            try:
                rid = json.loads(entries[0]["fields"]["data"]).get("run_id")
            except ValueError:
                rid = None
        if rid != b["run_id"]:
            self.find("run_id_mismatch", "run.start does not name the bundle's run")
            self.check(7, "run id", "fail", "mismatch")
        else:
            self.check(7, "run id", "pass", "run.start names the bundle's run")

    def expected_id(self, b):
        if b["anchor_id"] is None:
            return b["run_id"].encode()
        return hmac.new(b["anchor_id"], b["run_id"].encode(), "sha256").digest()

    def verify_anchors(self, b, heads):
        if not b["anchors"]:
            self.find("no_anchors", "the bundle has no anchors")
            self.check(8, "anchors", "info", "no anchors: nothing ties this journal to a time")
            return None
        latest = None
        try:
            latest = parse_checkpoint(parse_note(b["latest_checkpoint"] or "")[0])
        except (ValueError, TypeError) as e:
            self.find("anchor_consistency", f"latest_checkpoint is not a checkpoint: {e}")
        if latest is not None:
            self.find("not_checked", "the log's checkpoint signatures: " + NOT_CHECKED)
        ours = self.expected_id(b)
        prev = None
        for a in b["anchors"]:
            before = len(self.failures())
            leaf = self.anchor_leaf(a, ours, heads, prev)
            self.anchor_tree(a, latest)
            witnesses = self.witnesses(a)
            sound = len(self.failures()) == before
            trusted = sorted({w["operator"] for w in witnesses if w["class"] == "trusted"})
            times = [w["time_ns"] for w in witnesses if w["class"] == "trusted"]
            self.anchors.append({
                "seq": a["seq"], "entries": leaf["entries"] if leaf else 0, "sound": sound,
                "trusted_operators": trusted, "witnesses": witnesses,
                "independent": sound and len(trusted) >= self.min,
                "earliest_ns": min(times) if times else None})
            prev = (a, leaf)
        self.check(8, "anchors", "pass" if all(x["sound"] for x in self.anchors) else "fail",
                   f"{len(self.anchors)} anchor(s)")
        return latest

    def anchor_leaf(self, a, ours, heads, prev):
        seq = a["seq"]
        try:
            leaf = decode_leaf(a["leaf"])
        except ValueError as e:
            self.find("anchor_leaf", f"anchor {seq}: {e}")
            return None
        if leaf["kind"] != 0:
            self.find("anchor_leaf", f"anchor {seq}: the leaf is not a run leaf")
        if leaf["id"] != ours:
            self.find("run_id_mismatch", f"anchor {seq}: the leaf names another run")
        if leaf["entries"] >= len(heads) or heads[leaf["entries"]] != leaf["head"]:
            self.find("anchor_head_mismatch", f"anchor {seq}: the journal's head after {leaf['entries']} entries is not the leaf's head")
        if prev is None:
            if leaf["prev"] is not None:
                self.find("anchor_chain", f"anchor {seq}: the first anchor is not the run's first leaf")
        else:
            pa, pleaf = prev
            if leaf["prev"] != pa["leaf_index"]:
                self.find("anchor_chain", f"anchor {seq}: its leaf does not point to the previous anchor's leaf")
            if a["seq"] <= pa["seq"] or a["leaf_index"] <= pa["leaf_index"]:
                self.find("anchor_chain", f"anchor {seq}: anchors are not in log order")
            if pleaf and leaf["entries"] < pleaf["entries"]:
                self.find("anchor_chain", f"anchor {seq}: entries decrease")
        return leaf

    def anchor_tree(self, a, latest):
        seq = a["seq"]
        if not verify_inclusion(leaf_hash(a["leaf"]), a["leaf_index"], a["tree_size"], a["inclusion_proof"], a["root"]):
            self.find("anchor_inclusion", f"anchor {seq}: the inclusion proof does not lead to the root")
        try:
            body, _ = parse_note(a["checkpoint"])
            cp = parse_checkpoint(body)
        except ValueError as e:
            self.find("anchor_checkpoint", f"anchor {seq}: the checkpoint is malformed: {e}")
            a["body"] = None
        else:
            a["body"] = body
            if cp["tree_size"] != a["tree_size"] or cp["root"] != a["root"]:
                self.find("anchor_checkpoint", f"anchor {seq}: the checkpoint does not state the anchor's tree size and root")
            if latest is not None and cp["origin"] != latest["origin"]:
                self.find("anchor_checkpoint", f"anchor {seq}: the checkpoint is from another log")
            if sha256(body.encode()) != a["anchor_digest"]:
                self.find("anchor_digest", f"anchor {seq}: anchor_digest is not SHA-256 of the checkpoint body")
            a["checkpoint_parsed"] = cp
        if latest is not None and not verify_consistency(
                a["tree_size"], latest["tree_size"], a["root"], latest["root"], a["consistency"]):
            self.find("anchor_consistency", f"anchor {seq}: the consistency proof does not lead to latest_checkpoint")

    def witnesses(self, a):
        out = [{"type": "server-ed25519", "class": "operator-controlled", "operator": None,
                "time_ns": None, "detail": NOT_CHECKED}]
        seq = a["seq"]
        for w in a["witnesses"]:
            if w["type"] == "cosignature":
                try:
                    _, sigs = parse_note("x\n\n" + w["line"] + "\n")
                    if sigs[0][0] != w["name"]:
                        raise ValueError("the line names another witness")
                except (ValueError, IndexError) as e:
                    self.find("witness_malformed", f"anchor {seq}: a cosignature line is malformed: {e}")
                out.append({"type": "cosignature", "label": w["name"], "class": "self-asserted",
                            "operator": None, "time_ns": None, "detail": NOT_CHECKED})
                continue
            rep = {"type": "rfc3161", "label": w["tsa"], "class": "self-asserted", "operator": None,
                   "time_ns": None, "detail": ""}
            out.append(rep)
            try:
                info = tst_info(w["token"])
            except (ValueError, IndexError, StopIteration) as e:
                self.find("witness_malformed", f"anchor {seq}: a time-stamp token is malformed: {e}")
                continue
            rep["time_ns"] = info["time_ns"]
            if not info["sha256"] or info["hashed"] != a["anchor_digest"]:
                self.find("tsa_imprint_mismatch", f"anchor {seq}: a time-stamp token stamps something other than the anchor digest")
                continue
            if not check_certs_pem(w["certs_pem"]):
                self.find("witness_malformed", f"anchor {seq}: certs_pem is not PEM certificates")
                continue
            if not self.roots:
                rep["detail"] = "no TSA roots are pinned"
                self.find("tsa_untrusted", f"anchor {seq}: TSA {w['tsa']!r}: no TSA roots are pinned")
                continue
            last = ""
            for op, root in self.roots:
                self.index += 1
                ok, why = openssl_verify(w["token"], a["anchor_digest"], w["certs_pem"], root,
                                         info["gen_unix"] + 1, self.index)
                if why is None:
                    rep["detail"] = "openssl is not on PATH"
                    self.find("tsa_unchecked", f"anchor {seq}: TSA {w['tsa']!r}: not checked: openssl is not on PATH")
                    break
                if ok:
                    rep["class"], rep["operator"] = "trusted", operator(op)
                    rep["detail"] = f"verified against the pinned root for {rep['operator']}"
                    if operator(w["operator"]) != rep["operator"]:
                        self.find("operator_mismatch", f"anchor {seq}: the bundle names another operator than the pinned root")
                    break
                last = why
            else:
                rep["detail"] = f"does not verify against any pinned root ({last})"
                self.find("tsa_untrusted", f"anchor {seq}: TSA {w['tsa']!r}: {rep['detail']}")
        return out

    def full_log(self, b, latest):
        if self.log is None:
            return
        if latest is None:
            self.find("log_mismatch", "no latest checkpoint to check the log against")
            return
        leaves = self.log
        size = latest["tree_size"]
        if len(leaves) < size:
            self.find("log_mismatch", f"the log has {len(leaves)} leaves; the latest checkpoint covers {size}")
            return
        if mth([leaf_hash(x) for x in leaves[:size]]) != latest["root"]:
            self.find("log_mismatch", "the log's leaves do not hash to the latest checkpoint's root")
            return
        ours = self.expected_id(b)
        bundled = {a["leaf_index"]: a["leaf"] for a in b["anchors"]}
        before = len(self.failures())
        for i, d in enumerate(leaves):
            if i in bundled:
                if bundled[i] != d and i < size:
                    self.find("log_mismatch", f"the log's leaf {i} differs from the bundle's anchor")
                continue
            try:
                leaf = decode_leaf(d)
            except ValueError:
                continue
            if leaf["kind"] != 0 or leaf["id"] != ours:
                continue
            if i < size:
                self.find("anchor_omitted", f"the log's leaf {i} anchors this run at {leaf['entries']} entries, and the bundle leaves it out")
            else:
                self.find("log_newer", f"the log's leaf {i}, past the latest checkpoint, anchors this run")
        for a in b["anchors"]:
            if a["leaf_index"] >= size:
                self.find("log_mismatch", f"anchor {a['seq']} is past the latest checkpoint")
        ok = len(self.failures()) == before
        self.check(11, "full log (--log)", "pass" if ok else "fail", f"{size} leaves checked")

    def witness_log(self, b, wl, latest):
        if latest is not None and latest["origin"] != wl["origin"]:
            self.find("witness_log_origin", "the witness log is for another log origin")
            return
        before = len(self.failures())
        seen = {}
        for note in wl["checkpoints"]:
            try:
                cp = parse_checkpoint(parse_note(note)[0])
            except ValueError:
                continue
            if cp["origin"] != wl["origin"]:
                continue
            if cp["tree_size"] in seen and seen[cp["tree_size"]] != cp["root"]:
                self.find("witness_log_fork", f"the witness cosigned two roots for tree size {cp['tree_size']}")
            seen.setdefault(cp["tree_size"], cp["root"])
        ours = []
        for a in b["anchors"]:
            cp = a.get("checkpoint_parsed")
            if cp:
                cosigned = any(w["type"] == "cosignature" and w["name"] == wl["witness"] for w in a["witnesses"])
                ours.append((f"anchor {a['seq']}", cp, cosigned))
        if latest is not None:
            ours.append(("the latest checkpoint", latest, False))
        for what, cp, cosigned in ours:
            root = seen.get(cp["tree_size"])
            if root is not None and root != cp["root"]:
                self.find("witness_log_fork", f"{what}: the witness cosigned another root for tree size {cp['tree_size']}")
            elif root is None and cosigned:
                self.find("witness_log_mismatch", f"{what} carries a cosignature the witness's own log does not list")
        ok = len(self.failures()) == before
        self.check(11, "witness log (--witness-log)", "pass" if ok else "fail", wl["witness"])

    def result(self):
        if self.failures():
            verdict, code, anchored = "FAILED", 1, 0
        else:
            independent = [a["entries"] for a in self.anchors if a["independent"]]
            anchored = max(independent) if independent else 0
            if not independent:
                verdict, code = "UNANCHORED", 3
            elif anchored >= self.entries:
                verdict, code = "VERIFIED", 0
            else:
                verdict, code = "VERIFIED (PARTIAL)", 2
        self.checks.sort(key=lambda c: c["step"])
        return {"verdict": verdict, "exit": code, "entries": self.entries,
                "anchored_entries": min(anchored, self.entries), "min_operators": self.min,
                "checks": self.checks, "findings": self.findings, "anchors": self.anchors}


# -- command line ----------------------------------------------------------------


def clean(text):
    """Text from the bundle, safe to print: control characters escaped."""
    return "".join(c if c.isprintable() else f"\\u{{{ord(c):x}}}" for c in str(text))


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def load_log(path):
    doc = strict_json(read_file(path))
    if not isinstance(doc, dict) or list(doc) != ["leaves"] or not isinstance(doc["leaves"], list):
        raise Invalid("bundle_schema", f"{path} is not an anchor log")
    return [hexbytes(x, f"leaves[{i}]") for i, x in enumerate(doc["leaves"])]


def load_witness_log(path):
    doc = strict_json(read_file(path))
    obj(doc, "witness log", ["checkpoints", "origin", "witness"])
    return {"witness": string(doc["witness"], "witness"), "origin": string(doc["origin"], "origin"),
            "checkpoints": [string(c, "checkpoint") for c in array(doc["checkpoints"], "checkpoints")]}


def print_report(path, r):
    print(f"verify_evidence.py {path}")
    print()
    for c in r["checks"]:
        print(f"  [{c['status']}] {c['step']:>2} {c['name']}: {clean(c['detail'])}")
    for a in r["anchors"]:
        state = "independent" if a["independent"] else ("sound" if a["sound"] else "FAILS ITS CHECKS")
        print(f"  anchor {a['seq']}: {a['entries']} entries, {state}, trusted operators: "
              f"{', '.join(a['trusted_operators']) or 'none'}")
        for w in a["witnesses"]:
            label = clean(w.get("label", ""))[:40]
            print(f"    {w['type']:<15} {label:<40} {w['class']:<20} {w['operator'] or ''}")
    shown = [f for f in r["findings"] if f["severity"] != INFO or f["code"] == "not_checked"]
    if shown:
        print()
        for f in sorted(shown, key=lambda f: [FAILURE, WARNING, INFO].index(f["severity"])):
            print(f"  {f['severity']:<7} {f['code']}: {clean(f['message'])}")
    print()
    print(f"{r['verdict']}: {r['anchored_entries']} of {r['entries']} entries independently "
          f"anchored by at least {r['min_operators']} operator(s) (exit {r['exit']})")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("bundle", help="the bundle file, or a directory bundle")
    p.add_argument("--tsa-roots", action="append", default=[], metavar="[OPERATOR=]PEM")
    p.add_argument("--min-operators", type=int, default=2)
    p.add_argument("--log", metavar="FILE")
    p.add_argument("--witness-log", action="append", default=[], metavar="FILE")
    p.add_argument("--witness-key", action="append", default=[], metavar="OPERATOR=VKEY",
                   help="accepted for parity with pragmatic verify-evidence; Ed25519 is " + NOT_CHECKED)
    p.add_argument("--log-key", action="append", default=[], metavar="VKEY",
                   help="accepted for parity with pragmatic verify-evidence; Ed25519 is " + NOT_CHECKED)
    p.add_argument("--json", action="store_true", help="print the report as JSON")
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        return 64 if e.code else 0
    if args.min_operators < 1:
        print("error: --min-operators must be at least 1", file=sys.stderr)
        return 64
    roots = []
    for v in args.tsa_roots:
        op, sep, path = v.partition("=")
        if not sep or os.path.exists(v):
            op, path = os.path.splitext(os.path.basename(v))[0], v
        if not os.path.isfile(path):
            print(f"error: --tsa-roots: {path} is not a file", file=sys.stderr)
            return 64
        roots.append((op, path))
    try:
        log = load_log(args.log) if args.log else None
        wlogs = [load_witness_log(x) for x in args.witness_log]
    except (OSError, Invalid) as e:
        print(f"error: {e}", file=sys.stderr)
        return 64
    path = args.bundle
    directory = None
    if os.path.isdir(path):
        directory, path = path, os.path.join(path, "evidence.json")
    try:
        data = read_file(path)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    report = Verifier(roots, args.min_operators, log, wlogs).run(data, directory)
    if args.witness_key or args.log_key:
        report["findings"].append({
            "code": "not_checked", "severity": INFO,
            "message": "--witness-key and --log-key were given, but Ed25519 is " + NOT_CHECKED})
    if args.json:
        print(json.dumps(report, indent=1, default=str))
    else:
        print_report(path, report)
    return report["exit"]


if __name__ == "__main__":
    sys.exit(main())
