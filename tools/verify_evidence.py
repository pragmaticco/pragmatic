#!/usr/bin/env python3
"""Reference verifier for Pragmatic evidence bundles (pragmatic-evidence/1).

    python3 verify_evidence.py BUNDLE [--tsa-roots [OPERATOR=]PEM]...
        [--witness-key OPERATOR=VKEY]... [--log-key VKEY]...
        [--min-operators N] [--log FILE] [--witness-log FILE]... [--json]

An independent implementation of the checks in docs/evidence-format.md,
using only the Python standard library and the `openssl` command (for RFC
3161 time-stamp tokens). It reimplements journal format 2 parsing, strict
DER, Merkle proofs, C2SP signed notes and Ed25519 verification (RFC 8032,
in pure Python) from the specifications rather than calling Pragmatic, so a
bundle that passes both this and `pragmatic verify-evidence` has been
checked by two programs that share no code.

Exit codes: 0 VERIFIED, 2 VERIFIED (PARTIAL), 3 UNANCHORED, 1 FAILED,
64 usage error (including trust inputs that are malformed or unreadable).
"""

import argparse
import base64
import calendar
import datetime
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

FORMAT = "pragmatic-evidence/1"

FAILURE, WARNING, INFO = "failure", "warning", "info"
SEVERITY = {
    "bundle_json": FAILURE, "bundle_schema": FAILURE, "bundle_signature": FAILURE,
    "bundle_file": FAILURE,
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
    "witness_log_mismatch": FAILURE, "witness_log_origin": FAILURE,
    "witness_log_untrusted": FAILURE, "log_unauditable": FAILURE,
    "tsa_untrusted": WARNING, "tsa_unchecked": WARNING, "cosignature_untrusted": WARNING,
    "witness_key_expired": WARNING, "operator_mismatch": WARNING, "log_newer": WARNING,
    "anchor_id_unbound": WARNING,
    "unsigned": INFO, "operator_asserted": INFO, "no_anchors": INFO,
}
ALIASES = {"entrust": "sectigo", "quovadis-eu": "digicert"}
OPENSSL = os.environ.get("OPENSSL", "")
# The most bytes read from a file of a directory bundle (as the CLI).
MAX_BUNDLE_FILE = 16 << 30


class Invalid(Exception):
    """A bundle that cannot be read: (code, message)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class UsageError(Exception):
    """A problem with the verifier's own inputs: exit 64, never a verdict."""


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
    """The canonical serialization (format section 2): keys sorted by their
    UTF-8 bytes, no white space, and numbers exactly as they were written,
    so `-0` and `0` stay different, as they are to every other verifier."""
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-8"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical(v)
                              for k, v in items) + "}"
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, Int):
        return value.text
    if isinstance(value, int):
        return str(value)
    if isinstance(value, tuple):
        return value[1]
    return json.dumps(value, ensure_ascii=False)


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


RFC3339 = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]{1,9})?Z")


def days_in_month(year, month):
    if month == 2:
        return 29 if (year % 4 == 0 and year % 100 != 0) or year % 400 == 0 else 28
    return 30 if month in (4, 6, 9, 11) else 31


def is_rfc3339_utc(text):
    """`YYYY-MM-DDTHH:MM:SS[.f]Z` in UTC with ASCII digits and every field
    in range (no leap second), as the Rust verifier reads it."""
    m = RFC3339.fullmatch(text)
    if not m:
        return False
    y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
    return 1 <= mo <= 12 and 1 <= d <= days_in_month(y, mo) and h < 24 and mi < 60 and s < 60
BUNDLE_KEYS = ["anchor_id", "anchors", "format", "generated_at", "generator", "independent",
               "journal", "latest_checkpoint", "records", "redacted_slots", "redaction",
               "requested_by", "run_id", "signature", "verification_spec"]


def read_bundle(value):
    """Check the bundle's shape (section 3) and return it with bytes decoded."""
    b = obj(value, "bundle", BUNDLE_KEYS)
    if b["format"] != FORMAT:
        raise Invalid("bundle_schema", f"bundle.format is not {FORMAT!r}")
    if not is_rfc3339_utc(string(b["generated_at"], "bundle.generated_at")):
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


def prefix_roots(hashes, sizes):
    """The root of the tree of the first s leaves for each s in sizes (None
    beyond the leaves), in one pass: the frontier of perfect subtrees,
    folded from the right, is the RFC 6962 root of each size."""
    out = [None] * len(sizes)
    order = sorted(range(len(sizes)), key=lambda i: sizes[i])
    frontier, size, k = [], 0, 0
    while k < len(order):
        i = order[k]
        if sizes[i] == size:
            if not frontier:
                out[i] = sha256(b"")
            else:
                acc = frontier[-1][0]
                for left, _ in reversed(frontier[:-1]):
                    acc = node_hash(left, acc)
                out[i] = acc
            k += 1
            continue
        if size >= len(hashes):
            break
        node, height = hashes[size], 0
        while frontier and frontier[-1][1] == height:
            node = node_hash(frontier.pop()[0], node)
            height += 1
        frontier.append((node, height))
        size += 1
    return out


# -- Ed25519 (RFC 8032 section 5.1.7), verify only --------------------------------
#
# The same rules as the Rust verifier: the public key and R are canonical
# encodings of points that are not of small order, S is below L, and the
# cofactorless equation [S]B = R + [k]A holds. Variable time, which is fine:
# nothing verified here is secret.

ED_P = 2**255 - 19
ED_L = 2**252 + 27742317777372353535851937790883648493
ED_D = -121665 * pow(121666, ED_P - 2, ED_P) % ED_P
ED_SQRT_M1 = pow(2, (ED_P - 1) // 4, ED_P)
ED_IDENTITY = (0, 1, 1, 0)


def _ed_add(p, q):
    """Complete addition in extended coordinates (a = -1)."""
    a = (p[1] - p[0]) * (q[1] - q[0]) % ED_P
    b = (p[1] + p[0]) * (q[1] + q[0]) % ED_P
    c = 2 * p[3] * q[3] * ED_D % ED_P
    d = 2 * p[2] * q[2] % ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % ED_P, g * h % ED_P, f * g % ED_P, e * h % ED_P)


def _ed_mul(s, p):
    q = ED_IDENTITY
    while s > 0:
        if s & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        s >>= 1
    return q


def _ed_equal(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % ED_P == 0 and (p[1] * q[2] - q[1] * p[2]) % ED_P == 0


def _ed_decode(data):
    """Decompress a point; None for a non-canonical encoding (y >= p, or
    x = 0 with the sign bit set) or a y that is not on the curve."""
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= ED_P:
        return None
    x2 = (y * y - 1) * pow(ED_D * y * y + 1, ED_P - 2, ED_P) % ED_P
    if x2 == 0:
        if sign:
            return None
        return (0, y, 1, 0)
    x = pow(x2, (ED_P + 3) // 8, ED_P)
    if (x * x - x2) % ED_P != 0:
        x = x * ED_SQRT_M1 % ED_P
    if (x * x - x2) % ED_P != 0:
        return None
    if x & 1 != sign:
        x = ED_P - x
    return (x, y, 1, x * y % ED_P)


def _ed_prime_order(data):
    p = _ed_decode(data)
    if p is None or _ed_equal(_ed_mul(8, p), ED_IDENTITY):
        return None
    return p


_ED_B = _ed_decode((4 * pow(5, ED_P - 2, ED_P) % ED_P).to_bytes(32, "little"))


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= ED_L:
        return False
    a = _ed_prime_order(public)
    r = _ed_prime_order(signature[:32])
    if a is None or r is None:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % ED_L
    return _ed_equal(_ed_mul(s, _ED_B), _ed_add(r, _ed_mul(k, a)))


# -- leaves, signed notes, keys, checkpoints ---------------------------------------

LEAF_TAG = b"pragmatic/v2/leaf"
MAX_SIGNATURES = 100
# Unicode White_Space, which Rust's char::is_whitespace and Go's
# unicode.IsSpace both use (str.isspace differs).
WHITE_SPACE = set("\t\n\x0b\x0c\r \x85\xa0       "
                  "         　")
TYPE_ED25519, TYPE_COSIGNATURE = 0x01, 0x04


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


def canonical_b64(text):
    try:
        raw = base64.b64decode(text, validate=True)
    except ValueError:
        return None
    return raw if base64.b64encode(raw).decode() == text else None


def valid_key_name(name):
    return bool(name) and not any(c in WHITE_SPACE or c == "+" or c < " " for c in name)


def parse_signature_line(line):
    """One signed-note signature line: (name, key id, signature bytes)."""
    if any(c < " " for c in line):
        raise ValueError("control character in signature line")
    if not line.startswith("— "):
        raise ValueError("signature line does not start with an em dash and a space")
    name, sep, b64 = line[2:].partition(" ")
    if not sep:
        raise ValueError("signature line has no signature")
    if not valid_key_name(name):
        raise ValueError("invalid key name")
    raw = canonical_b64(b64)
    if raw is None:
        raise ValueError("signature is not canonical base64")
    if len(raw) < 5:
        raise ValueError("signature too short")
    return (name, raw[:4], raw[4:])


def parse_note(text):
    """Split a signed note into (body, [(name, key id, signature bytes)])."""
    if any(c < " " and c != "\n" for c in text):
        raise ValueError("control character in note")
    split = text.rfind("\n\n")
    if split < 0:
        raise ValueError("no blank line before the signatures")
    body, block = text[:split + 1], text[split + 2:]
    if not block.endswith("\n"):
        raise ValueError("signatures do not end in a newline")
    sigs = []
    for line in block[:-1].split("\n"):
        if len(sigs) == MAX_SIGNATURES:
            raise ValueError("too many signatures")
        sigs.append(parse_signature_line(line))
    return body, sigs


def parse_checkpoint(body):
    if not body.endswith("\n"):
        raise ValueError("checkpoint does not end in a newline")
    if any(c < " " and c != "\n" for c in body):
        raise ValueError("control character in checkpoint")
    lines = body[:-1].split("\n")
    if len(lines) < 3 or any(not l for l in lines):
        raise ValueError("checkpoint has fewer than three lines or an empty line")
    if not UINT.fullmatch(lines[1]) or int(lines[1]) >= 2**64:
        raise ValueError("tree size is not a canonical decimal")
    root = canonical_b64(lines[2])
    if root is None or len(root) != 32:
        raise ValueError("root is not canonical base64 of 32 bytes")
    return {"origin": lines[0], "tree_size": int(lines[1]), "root": root}


def make_key(name, sig_type, public):
    if not valid_key_name(name):
        raise ValueError("invalid key name")
    if sig_type == TYPE_COSIGNATURE and len(name.encode()) > 255:
        raise ValueError("cosigner name is longer than 255 bytes")
    if _ed_prime_order(public) is None:
        raise ValueError("public key is not a valid Ed25519 point of large order")
    kid = sha256(name.encode() + b"\n" + bytes([sig_type]) + public)[:4]
    return {"name": name, "id": kid, "type": sig_type, "public": public}


def parse_vkey(text):
    """A C2SP verifier key: <name>+<hex key id>+<base64(type || key)>."""
    name, sep, rest = text.partition("+")
    id_hex, sep2, key_b64 = rest.partition("+")
    if not sep or not sep2:
        raise ValueError("expected <name>+<key id>+<key>")
    if not valid_key_name(name):
        raise ValueError("invalid key name")
    if not re.fullmatch(r"[0-9a-f]{8}", id_hex):
        raise ValueError("key id is not eight lowercase hex digits")
    raw = canonical_b64(key_b64)
    if not raw:
        raise ValueError("key is not canonical base64")
    if raw[0] not in (TYPE_ED25519, TYPE_COSIGNATURE):
        raise ValueError("unsupported signature type")
    if len(raw) != 33:
        raise ValueError("Ed25519 public key is not 32 bytes")
    key = make_key(name, raw[0], raw[1:])
    if key["id"].hex() != id_hex:
        raise ValueError("key id does not match the name, type and key")
    return key


def key_verifies(key, body, sig):
    """Whether one signature line (already matched by name and key id)
    verifies over a note body."""
    if key["type"] == TYPE_ED25519:
        return len(sig) == 64 and ed25519_verify(key["public"], body.encode(), sig)
    if len(sig) != 72:
        return False
    ts = int.from_bytes(sig[:8], "big")
    message = f"cosignature/v1\ntime {ts}\n".encode() + body.encode()
    return ed25519_verify(key["public"], message, sig[8:])


def verify_note(body, sigs, keys):
    """The signed-note rules, as the Rust verifier applies them: lines from
    unknown keys are ignored, every line from a known key must verify, two
    different lines from one key reject the note, and at least one known
    key must have signed. Returns [(key index, timestamp or None)]."""
    verified = []
    for index, (name, kid, sig) in enumerate(sigs):
        matching = [(i, k) for i, k in enumerate(keys) if k["name"] == name and k["id"] == kid]
        if not matching:
            continue
        ki, key = matching[0]
        if any(k != key for _, k in matching[1:]):
            raise ValueError(f"ambiguous key {name}")
        if not key_verifies(key, body, sig):
            raise ValueError(f"invalid signature from {name}")
        first = next((v for v in verified if v[0] == ki), None)
        if first is None:
            ts = int.from_bytes(sig[:8], "big") if key["type"] == TYPE_COSIGNATURE else None
            verified.append((ki, index, ts))
        elif sigs[first[1]][2] != sig:
            raise ValueError(f"two different signatures from {name}")
    if not verified:
        raise ValueError("no signature from a pinned key")
    return [(ki, ts) for ki, _, ts in verified]


def signed_by_log(body, sigs, origin, keys):
    """None if a pinned log key signed the checkpoint under its own origin,
    otherwise why not (a log signs as its origin; a key signs any origin
    line it is given)."""
    try:
        signed = verify_note(body, sigs, keys)
    except ValueError as e:
        return f"is not signed by a pinned log key: {e}"
    if any(keys[ki]["name"] == origin for ki, _ in signed):
        return None
    return (f"names the origin {origin!r}, but the pinned log key that signed it is named "
            f"{keys[signed[0][0]]['name']!r}: a log signs only checkpoints of its own origin")


# -- RFC 3161 tokens: strict DER and openssl --------------------------------------
#
# The same rules as the Rust verifier: the whole token is checked as DER
# before any field is read (minimal definite lengths, single-byte tags, no
# end-of-contents, SEQUENCE and SET constructed and other universal types
# primitive, minimal INTEGERs, canonical BOOLEANs, empty NULLs, nesting at
# most 64 deep), then the fields this verifier reads are checked against
# RFC 3161. A token two parsers could read differently is refused.

DER_MAX_DEPTH = 64
SHA256_OID = bytes.fromhex("608648016503040201")
SIGNED_DATA_OID = bytes.fromhex("2a864886f70d010702")
TST_INFO_OID = bytes.fromhex("2a864886f70d0109100104")


def der(data, pos=0):
    """One TLV at pos: (tag, value, end). Strict DER lengths."""
    if pos >= len(data):
        raise ValueError("DER ends early")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise ValueError("multi-byte tag")
    if pos + 1 >= len(data):
        raise ValueError("DER ends early")
    first = data[pos + 1]
    pos += 2
    if first < 0x80:
        n = first
    elif first == 0x80:
        raise ValueError("indefinite length")
    else:
        count = first & 0x7F
        if count > 4:
            raise ValueError("length longer than four octets")
        if pos + count > len(data):
            raise ValueError("DER ends early")
        octets = data[pos:pos + count]
        if octets[0] == 0:
            raise ValueError("length with leading zero octet")
        n = int.from_bytes(octets, "big")
        if n < 0x80:
            raise ValueError("long-form length below 128")
        pos += count
    if pos + n > len(data):
        raise ValueError("DER value exceeds its container")
    return tag, data[pos:pos + n], pos + n


def integer_bytes(value):
    if not value:
        raise ValueError("empty INTEGER")
    if len(value) > 1 and ((value[0] == 0 and not value[1] & 0x80)
                           or (value[0] == 0xFF and value[1] & 0x80)):
        raise ValueError("non-minimal INTEGER")
    return value


def check_der(data, depth=0):
    if depth > DER_MAX_DEPTH:
        raise ValueError("nested too deep")
    pos = 0
    while pos < len(data):
        tag, value, pos = der(data, pos)
        constructed = bool(tag & 0x20)
        if tag == 0:
            raise ValueError("end-of-contents marker")
        if tag & 0xC0 == 0:
            if tag in (0x30, 0x31):
                pass
            elif tag in (0x10, 0x11):
                raise ValueError("primitive SEQUENCE or SET")
            elif constructed:
                raise ValueError("constructed universal type")
            elif tag == 0x02:
                integer_bytes(value)
            elif tag == 0x01 and value not in (b"\x00", b"\xff"):
                raise ValueError("BOOLEAN must be one octet, 0x00 or 0xff")
            elif tag == 0x05 and value:
                raise ValueError("NULL with content")
        if constructed:
            check_der(value, depth + 1)


class DerReader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def peek(self):
        return self.data[self.pos] if self.pos < len(self.data) else None

    def next(self, field):
        if self.pos >= len(self.data):
            raise ValueError(f"{field} is missing")
        tag, value, self.pos = der(self.data, self.pos)
        return tag, value

    def expect(self, tag, field):
        found = self.peek()
        if found is None:
            raise ValueError(f"{field} is missing")
        if found != tag:
            raise ValueError(f"{field} has tag {found:#x}, not {tag:#x}")
        return self.next(field)[1]

    def optional(self, tag, field):
        return self.next(field)[1] if self.peek() == tag else None

    def finish(self, after):
        if self.pos != len(self.data):
            raise ValueError(f"trailing data after {after}")


def single(data, tag, field):
    r = DerReader(data)
    value = r.expect(tag, field)
    r.finish(field)
    return value


def oid(value):
    """The OID's content octets, checked: not empty, no arc with a leading
    0x80, none that ends mid-arc or exceeds 64 bits."""
    if not value:
        raise ValueError("empty OBJECT IDENTIFIER")
    arc, fresh = 0, True
    for b in value:
        if fresh and b == 0x80:
            raise ValueError("OBJECT IDENTIFIER arc with leading 0x80")
        if arc > (2**64 - 1) >> 7:
            raise ValueError("OBJECT IDENTIFIER arc too large")
        arc = (arc << 7) | (b & 0x7F)
        fresh = not b & 0x80
        if fresh:
            arc = 0
    if not fresh:
        raise ValueError("OBJECT IDENTIFIER ends mid-arc")
    return value


def integer_u64(value):
    """A non-negative INTEGER that fits 64 bits, or None."""
    b = integer_bytes(value)
    if b[0] & 0x80:
        return None
    if b[0] == 0 and len(b) > 1:
        b = b[1:]
    return int.from_bytes(b, "big") if len(b) <= 8 else None


def generalized_time(text):
    """RFC 3161 genTime (YYYYMMDDhhmmss[.f]Z) as (unix seconds, nanos)."""
    m = re.fullmatch(rb"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\.([0-9]+))?Z",
                     text)
    if not m:
        raise ValueError("malformed genTime")
    y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
    if not (1 <= mo <= 12 and 1 <= d <= days_in_month(y, mo) and h <= 23 and mi <= 59 and s <= 60):
        raise ValueError("genTime out of range")
    frac = int((m.group(7) or b"0").decode().ljust(9, "0")[:9])
    return calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0)), frac


def accuracy_ns(value):
    if not value:
        raise ValueError("accuracy with no fields")
    r = DerReader(value)
    total = 0
    seconds = r.optional(0x02, "accuracy seconds")
    if seconds is not None:
        v = integer_u64(seconds)
        if v is None:
            raise ValueError("accuracy seconds out of range")
        total += v * 10**9
    for tag, scale in ((0x80, 10**6), (0x81, 10**3)):
        part = r.optional(tag, "accuracy part")
        if part is not None:
            v = integer_u64(part)
            if v is None or not 1 <= v <= 999:
                raise ValueError("accuracy millis or micros out of range")
            total += v * scale
    r.finish("accuracy")
    return total


def tst_info(token):
    """The fields of a token's TSTInfo this verifier needs, after checking
    the whole token as strict DER (RFC 3161 section 2.4.2, RFC 5652).
    Signatures are left to openssl."""
    check_der(token)
    ci = DerReader(single(token, 0x30, "ContentInfo"))
    if oid(ci.expect(0x06, "contentType")) != SIGNED_DATA_OID:
        raise ValueError("token content type is not signedData")
    explicit = ci.expect(0xA0, "content")
    ci.finish("ContentInfo")
    sd = DerReader(single(explicit, 0x30, "SignedData"))
    integer_bytes(sd.expect(0x02, "SignedData version"))
    sd.expect(0x31, "digestAlgorithms")
    encap = sd.expect(0x30, "encapContentInfo")
    sd.optional(0xA0, "certificates")
    sd.optional(0xA1, "crls")
    sd.expect(0x31, "signerInfos")
    sd.finish("SignedData")
    ec = DerReader(encap)
    if oid(ec.expect(0x06, "eContentType")) != TST_INFO_OID:
        raise ValueError("encapsulated content is not TSTInfo")
    explicit = ec.expect(0xA0, "eContent")
    ec.finish("encapContentInfo")
    der_info = single(explicit, 0x04, "eContent")
    check_der(der_info)
    t = DerReader(single(der_info, 0x30, "TSTInfo"))
    if integer_u64(t.expect(0x02, "version")) != 1:
        raise ValueError("unsupported TSTInfo version")
    oid(t.expect(0x06, "policy"))
    mi = DerReader(t.expect(0x30, "messageImprint"))
    alg = DerReader(mi.expect(0x30, "hashAlgorithm"))
    hashed = mi.expect(0x04, "hashedMessage")
    mi.finish("messageImprint")
    algorithm = oid(alg.expect(0x06, "hashAlgorithm"))
    alg.optional(0x05, "hashAlgorithm parameters")
    alg.finish("hashAlgorithm")
    serial = integer_bytes(t.expect(0x02, "serialNumber"))
    if serial[0] & 0x80:
        raise ValueError("negative serial number")
    gen_unix, gen_nanos = generalized_time(t.expect(0x18, "genTime"))
    accuracy = t.optional(0x30, "accuracy")
    extra = accuracy_ns(accuracy) if accuracy is not None else 0
    ordering = t.optional(0x01, "ordering")
    if ordering == b"\x00":
        raise ValueError("ordering FALSE must be omitted")
    nonce = t.optional(0x02, "nonce")
    if nonce is not None:
        integer_bytes(nonce)
    tsa = t.optional(0xA0, "tsa")
    if tsa is not None:
        inner = DerReader(tsa)
        inner.next("tsa")
        inner.finish("tsa")
    t.optional(0xA1, "extensions")
    t.finish("TSTInfo")
    return {"sha256": algorithm == SHA256_OID, "hashed": hashed, "gen_unix": gen_unix,
            "time_ns": gen_unix * 10**9 + gen_nanos + extra}


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
            if not body or canonical_b64(body) is None:
                return False
            body = None
        else:
            if not line or len(line) > 64:
                return False
            body += line
    return body is None


def openssl_capability(binary):
    """None if `binary` can check tokens as step 9 needs (OpenSSL, not
    LibreSSL, whose `ts` has no -attime), otherwise why not."""
    def run(*args):
        p = subprocess.run([binary, *args], capture_output=True, stdin=subprocess.DEVNULL)
        return (p.stdout + p.stderr).decode(errors="replace")
    try:
        lines = run("version").strip().splitlines()
        version = lines[0] if lines else "version unknown"
        if "LibreSSL" in version:
            return f"{version}, whose ts -verify cannot check a token at its signing time (no -attime)"
        if "-attime" not in run("ts", "-help"):
            return f"{binary} ({version}) has no ts -verify -attime"
    except OSError as e:
        return f"cannot run {binary}: {e}"
    return None


def find_openssl():
    """(binary, None) for the first openssl that can check tokens ($OPENSSL
    if set, otherwise the first on PATH), or (None, why not)."""
    if OPENSSL:
        candidates = [OPENSSL]
    else:
        candidates = []
        for d in os.environ.get("PATH", "").split(os.pathsep):
            p = os.path.join(d, "openssl")
            if os.path.isabs(d) and os.path.isfile(p) and os.access(p, os.X_OK) and p not in candidates:
                candidates.append(p)
    if not candidates or (OPENSSL and shutil.which(OPENSSL) is None):
        return None, "openssl is not on PATH"
    first_why = None
    for c in candidates:
        why = openssl_capability(c)
        if why is None:
            return c, None
        first_why = first_why or why
    return None, first_why


_OPENSSL_FOUND = {}


def openssl_binary():
    """find_openssl, once per value of OPENSSL."""
    if OPENSSL not in _OPENSSL_FOUND:
        _OPENSSL_FOUND[OPENSSL] = find_openssl()
    return _OPENSSL_FOUND[OPENSSL]


def openssl_verify(token, digest, certs_pem, root, at_time, index):
    """openssl ts -verify, exactly as section 8 step 9 says. Returns
    (verified, reason); reason is None when the token could not be checked
    (no usable openssl, or openssl did not run the check), which leaves it
    unchecked rather than rejected."""
    binary, why = openssl_binary()
    if binary is None:
        return False, None, why
    hexdigest = digest.hex()
    if not re.fullmatch(r"[0-9a-f]{64}", hexdigest):
        return False, "digest is not 64 lowercase hex digits", None
    if at_time < 0:
        return False, "genTime is before 1970", None
    work = tempfile.mkdtemp(prefix="pragmatic-tsa-")  # mode 0700
    try:
        tok = os.path.join(work, f"{index}.der")
        with open(tok, "wb") as f:
            f.write(token)
        args = [binary, "ts", "-verify", "-token_in", "-in", tok, "-digest", hexdigest,
                "-CAfile", os.path.abspath(root), "-attime", str(at_time)]
        if certs_pem.strip():
            pem = os.path.join(work, f"{index}.pem")
            with open(pem, "w") as f:
                f.write(certs_pem)
            args += ["-untrusted", pem]
        p = subprocess.run(args, capture_output=True, stdin=subprocess.DEVNULL)
        err = p.stderr.decode(errors="replace").strip().splitlines()
        reason = next((l for l in err if "rror" in l), err[0] if err else "openssl ts -verify failed")
        reason = reason.rsplit(":", 1)[-1].strip()
        if p.returncode == 0 and b"Verification: OK" in p.stdout:
            return True, "", None
        if b"Verification: FAILED" in p.stdout:
            return False, reason, None
        return False, None, f"openssl did not run the check ({reason})"
    finally:
        shutil.rmtree(work, ignore_errors=True)


def normalize(name):
    """An operator name for comparison, as the Rust verifier: trimmed, lower
    case, each run of white space and `_` one `-` (never a leading one)."""
    out, gap = [], False
    for c in name.strip("".join(WHITE_SPACE)):
        if c in WHITE_SPACE or c == "_":
            gap = True
            continue
        if gap and out:
            out.append("-")
        gap = False
        out.append(c.lower())
    return "".join(out)


def operator(name):
    n = normalize(name)
    return ALIASES.get(n, n)


def rfc3339(ns):
    secs, frac = divmod(ns, 10**9)
    t = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=secs)
    out = t.strftime("%Y-%m-%dT%H:%M:%S")
    if frac:
        out += "." + f"{frac:09d}".rstrip("0")
    return out + "Z"


# -- the procedure -------------------------------------------------------------------


def read_bundle_file(path):
    """A file inside a directory bundle: only a regular file (not a link, a
    FIFO or a device; the directory came from the party being audited) of
    at most MAX_BUNDLE_FILE bytes. Returns bytes, None if it is absent, or
    raises Invalid("bundle_file"). Other errors raise UsageError."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise UsageError(f"cannot read {path}: {e}")
    if not stat.S_ISREG(st.st_mode):
        raise Invalid("bundle_file", f"{path} is not a regular file (a symbolic link, FIFO or "
                                     "device in a bundle directory is never read)")
    if st.st_size > MAX_BUNDLE_FILE:
        raise Invalid("bundle_file", f"{path} is {st.st_size} bytes, more than any bundle holds")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise UsageError(f"cannot read {path}: {e}")
    with os.fdopen(fd, "rb") as f:
        fst = os.fstat(f.fileno())
        if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
            raise Invalid("bundle_file", f"{path} changed while it was being opened")
        data = f.read(MAX_BUNDLE_FILE + 1)
    if len(data) > MAX_BUNDLE_FILE:
        raise Invalid("bundle_file", f"{path} grew past the size limit")
    return data


class Verifier:
    def __init__(self, roots, min_operators, log=None, witness_logs=(), witness_keys=(),
                 log_keys=()):
        self.roots = roots  # [(operator, path)]
        self.min = min_operators
        self.log = log
        self.witness_logs = list(witness_logs)
        self.witness_keys = list(witness_keys)  # [(operator, key)]
        self.log_keys = list(log_keys)  # [key]
        self.findings, self.checks, self.anchors = [], [], []
        self.entries = 0
        self.index = 0
        self.signature = "unsigned"

    def find(self, code, message):
        self.findings.append({"code": code, "severity": SEVERITY[code], "message": message})

    def check(self, step, name, status, detail):
        self.checks.append({"step": step, "name": name, "status": status, "detail": detail})

    def fail(self, step, name, code, message):
        self.find(code, message)
        self.check(step, name, "fail", message)

    def failures(self):
        return [f for f in self.findings if f["severity"] == FAILURE]

    def run(self, data, directory=None):
        try:
            b = read_bundle(strict_json(data))
        except Invalid as e:
            self.fail(1, "strict JSON, known keys", e.code, e.message)
            return self.result()
        self.run_id = b["run_id"]
        self.check(1, "strict JSON, known keys", "pass", "exactly the keys of " + FORMAT)
        self.bundle_signature(b)
        journal = b["journal"]
        if journal is None:
            path, digest = b["journal_file"]
            try:
                journal = read_bundle_file(os.path.join(directory or ".", path))
            except Invalid as e:
                self.fail(2, "bundle files", e.code, e.message)
                return self.result()
            if journal is None or sha256(journal) != digest:
                self.fail(2, "journal parses canonically", "journal_missing",
                          "the bundle's journal file is missing or does not match its sha256")
                return self.result()
        try:
            entries, heads = parse_journal(journal)
        except Invalid as e:
            self.fail(2, "journal parses canonically", e.code, e.message)
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
        hashes = self.full_log(b, latest)
        for wl in self.witness_logs:
            self.witness_log(b, wl, latest, hashes)
        return self.result()

    # -- step 1 -----------------------------------------------------------------

    def bundle_signature(self, b):
        """A pinned log key says which log the bundle comes from: such a
        bundle is signed, and only the signature covers the fields no other
        check reaches."""
        sig = b["signature"]
        pinned = bool(self.log_keys)
        name = "bundle signature"
        if sig is None:
            self.signature = "unsigned"
            if pinned:
                self.fail(1, name, "bundle_signature",
                          "the bundle is unsigned, but a log key is pinned: a bundle from that log is "
                          "signed, and without the signature its unsigned fields could have been "
                          "changed by anyone")
            else:
                self.find("unsigned", "the bundle is not signed")
                self.check(1, name, "info", "unsigned")
            return
        raw = dict(b["raw"])
        del raw["signature"]
        message = sha256(canonical(raw).encode())
        public = bytes.fromhex(sig["public_key"])
        key = next((k for k in self.log_keys if k["public"] == public), None)
        valid = ed25519_verify(public, message, bytes.fromhex(sig["value"]))
        if key is not None and valid and key["id"].hex() == sig["key_id"]:
            self.signature = "verified"
            self.check(1, name, "pass", f"verified with the pinned log key {key['name']}")
        elif key is not None or not valid:
            self.signature = "invalid"
            self.fail(1, name, "bundle_signature",
                      "the bundle signature does not verify with the pinned log key" if key is not None
                      else "the bundle signature does not verify even with the key it names")
        elif pinned:
            self.signature = "operator-asserted"
            self.fail(1, name, "bundle_signature",
                      "the bundle is signed by a key that is not pinned: the pinned log key did not sign it")
        else:
            self.signature = "operator-asserted"
            self.find("operator_asserted", "the bundle signature's key is not pinned (pass --log-key)")
            self.check(1, name, "info", "valid, but its key is not pinned: operator-asserted")

    # -- steps 4 to 7 ------------------------------------------------------------

    def withheld(self, b, entries):
        actual = [(e["cursor"], k) for e in entries for k, s in enumerate(e["slots"]) if s["state"] == "withheld"]
        if b["redacted_slots"] != actual:
            self.fail(4, "withheld slots", "withheld_mismatch", "redacted_slots does not equal the withheld slots")
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
            self.fail(6, "records equal the journal", "records_mismatch", "records differ from the decoded journal")
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
            self.fail(7, "run id", "run_id_mismatch", "run.start does not name the bundle's run")
        else:
            self.check(7, "run id", "pass", "run.start names the bundle's run")
        if b["anchor_id"] is not None:
            self.find("anchor_id_unbound",
                      "the log names this run by HMAC under the per-run key in anchor_id, which the "
                      "bundle supplies and nothing binds to the run: anchors made under another key "
                      "cannot be told apart from other runs' leaves, so hidden or re-keyed anchors "
                      "cannot be detected, not even with --log")

    def expected_id(self, b):
        if b["anchor_id"] is None:
            return b["run_id"].encode()
        return hmac.new(b["anchor_id"], b["run_id"].encode(), "sha256").digest()

    # -- steps 8 to 10 -----------------------------------------------------------

    def log_signature(self, body, sigs, origin, what):
        if not self.log_keys:
            return
        why = signed_by_log(body, sigs, origin, self.log_keys)
        if why is not None:
            self.find("log_signature", f"{what} {why}")

    def verify_anchors(self, b, heads):
        if not b["anchors"]:
            self.find("no_anchors", "the bundle has no anchors")
            self.check(8, "anchors", "info", "no anchors: nothing ties this journal to a time")
            return None
        latest = None
        try:
            body, sigs = parse_note(b["latest_checkpoint"] or "")
            latest = parse_checkpoint(body)
        except (ValueError, TypeError) as e:
            self.find("anchor_consistency", f"latest_checkpoint is not a checkpoint: {e}")
        else:
            self.log_signature(body, sigs, latest["origin"], "the latest checkpoint")
        ours = self.expected_id(b)
        prev = None
        for a in b["anchors"]:
            before = len(self.failures())
            leaf = self.anchor_leaf(a, ours, heads, prev)
            self.anchor_tree(a, latest)
            witnesses = self.witnesses(a)
            sound = len(self.failures()) == before
            trusted = sorted({w["operator"] for w in witnesses if w["class"] == "trusted"})
            self.anchors.append({
                "seq": a["seq"], "entries": leaf["entries"] if leaf else 0, "sound": sound,
                "trusted_operators": trusted, "witnesses": witnesses,
                "independent": sound and len(trusted) >= self.min,
                "time_ns": vouched_time(witnesses, self.min)})
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
        a["body"] = None
        if not verify_inclusion(leaf_hash(a["leaf"]), a["leaf_index"], a["tree_size"], a["inclusion_proof"], a["root"]):
            self.find("anchor_inclusion", f"anchor {seq}: the inclusion proof does not lead to the root")
        try:
            body, sigs = parse_note(a["checkpoint"])
            cp = parse_checkpoint(body)
        except ValueError as e:
            self.find("anchor_checkpoint", f"anchor {seq}: the checkpoint is malformed: {e}")
        else:
            a["body"] = body
            if cp["tree_size"] != a["tree_size"] or cp["root"] != a["root"]:
                self.find("anchor_checkpoint", f"anchor {seq}: the checkpoint does not state the anchor's tree size and root")
            if latest is not None and cp["origin"] != latest["origin"]:
                self.find("anchor_checkpoint", f"anchor {seq}: the checkpoint is from another log")
            if sha256(body.encode()) != a["anchor_digest"]:
                self.find("anchor_digest", f"anchor {seq}: anchor_digest is not SHA-256 of the checkpoint body")
            self.log_signature(body, sigs, cp["origin"], f"anchor {seq}'s checkpoint")
            a["checkpoint_parsed"] = cp
        if latest is not None and not verify_consistency(
                a["tree_size"], latest["tree_size"], a["root"], latest["root"], a["consistency"]):
            self.find("anchor_consistency", f"anchor {seq}: the consistency proof does not lead to latest_checkpoint")

    def witnesses(self, a):
        out = []
        if a["body"] is None:
            return out
        out.append({"type": "server-ed25519", "label": "", "class": "operator-controlled",
                    "operator": None, "time_ns": None,
                    "detail": "the log's checkpoint signature"})
        for w in a["witnesses"]:
            if w["type"] == "cosignature":
                out.append(self.cosignature(a, w))
            else:
                out.append(self.tsa_witness(a, w))
        return out

    def cosignature(self, a, w):
        seq = a["seq"]
        rep = {"type": "cosignature", "label": w["name"], "class": "self-asserted",
               "operator": None, "time_ns": None, "detail": ""}
        try:
            name, kid, sig = parse_signature_line(w["line"])
        except ValueError as e:
            rep["detail"] = f"anchor {seq}: a cosignature line is malformed: {e}"
            self.find("witness_malformed", rep["detail"])
            return rep
        if name != w["name"]:
            rep["detail"] = f"anchor {seq}: a cosignature line names another witness than its entry"
            self.find("witness_malformed", rep["detail"])
            return rep
        matching = [(op, k) for op, k in self.witness_keys if k["name"] == name and k["id"] == kid]
        if not matching:
            rep["detail"] = f"no pinned witness key for {name!r} with this key id (pass --witness-key)"
            self.find("cosignature_untrusted", f"anchor {seq}: {rep['detail']}")
            return rep
        op = next((op for op, k in matching if key_verifies(k, a["body"], sig)), None)
        if op is None:
            rep["detail"] = f"anchor {seq}: the cosignature from {name!r} does not verify with its pinned key"
            self.find("cosignature_invalid", rep["detail"])
            return rep
        rep["class"], rep["operator"] = "trusted", operator(op)
        rep["time_ns"] = int.from_bytes(sig[:8], "big") * 10**9 if len(sig) == 72 else None
        rep["detail"] = f"verified with the pinned key for {rep['operator']}"
        return rep

    def tsa_witness(self, a, w):
        seq = a["seq"]
        rep = {"type": "rfc3161", "label": w["tsa"], "class": "self-asserted", "operator": None,
               "time_ns": None, "detail": ""}
        try:
            info = tst_info(w["token"])
        except (ValueError, IndexError) as e:
            self.find("witness_malformed", f"anchor {seq}: a time-stamp token is malformed: {e}")
            return rep
        rep["time_ns"] = info["time_ns"]
        if not info["sha256"] or info["hashed"] != a["anchor_digest"]:
            self.find("tsa_imprint_mismatch", f"anchor {seq}: a time-stamp token stamps something other than the anchor digest")
            return rep
        if not check_certs_pem(w["certs_pem"]):
            self.find("witness_malformed", f"anchor {seq}: certs_pem is not PEM certificates")
            return rep
        if not self.roots:
            rep["detail"] = "no TSA roots are pinned"
            self.find("tsa_untrusted", f"anchor {seq}: TSA {w['tsa']!r}: no TSA roots are pinned")
            return rep
        last = ""
        for op, root in self.roots:
            self.index += 1
            ok, why, unchecked = openssl_verify(w["token"], a["anchor_digest"], w["certs_pem"], root,
                                                info["gen_unix"] + 1, self.index)
            if unchecked is not None:
                rep["detail"] = f"not checked: {unchecked}"
                self.find("tsa_unchecked", f"anchor {seq}: TSA {w['tsa']!r}: {rep['detail']}")
                return rep
            if ok:
                rep["class"], rep["operator"] = "trusted", operator(op)
                rep["detail"] = f"verified against the pinned root for {rep['operator']}"
                if operator(w["operator"]) != rep["operator"]:
                    self.find("operator_mismatch", f"anchor {seq}: the bundle names another operator than the pinned root")
                return rep
            last = why
        rep["detail"] = f"does not verify against any pinned root ({last})"
        self.find("tsa_untrusted", f"anchor {seq}: TSA {w['tsa']!r}: {rep['detail']}")
        return rep

    # -- step 11 -------------------------------------------------------------------

    def full_log(self, b, latest):
        """The --log audit. Returns every leaf's hash once the log is shown
        to reach the latest checkpoint's root, for the witness-log audit."""
        if self.log is None:
            return None
        name = "full log (--log)"
        if latest is None:
            self.fail(11, name, "log_mismatch", "no latest checkpoint to check the log against")
            return None
        leaves = self.log
        size = latest["tree_size"]
        if len(leaves) < size:
            self.fail(11, name, "log_mismatch", f"the log has {len(leaves)} leaves; the latest checkpoint covers {size}")
            return None
        hashes = [leaf_hash(x) for x in leaves]
        if mth(hashes[:size]) != latest["root"]:
            self.fail(11, name, "log_mismatch", "the log's leaves do not hash to the latest checkpoint's root")
            return None
        before = len(self.failures())
        for a in b["anchors"]:
            if a["leaf_index"] >= size:
                self.find("log_mismatch", f"anchor {a['seq']} is past the latest checkpoint")
            elif leaves[a["leaf_index"]] != a["leaf"]:
                self.find("log_mismatch", f"the log's leaf {a['leaf_index']} differs from the bundle's anchor")
        if b["anchor_id"] is not None:
            self.fail(11, name, "log_unauditable",
                      "the bundle names the run by HMAC under a key it supplies itself (anchor_id), and "
                      "nothing binds that key to the run, so the log cannot show anchors made under "
                      "another key: hidden or re-keyed anchors cannot be ruled out")
            return hashes
        ours = self.expected_id(b)
        bundled = {a["leaf_index"] for a in b["anchors"]}
        for i, d in enumerate(leaves):
            if i in bundled:
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
        ok = len(self.failures()) == before
        self.check(11, name, "pass" if ok else "fail",
                   f"all {size} leaves hash to the latest root; every leaf of this run is in the bundle"
                   if ok else "the log shows anchors the bundle does not account for")
        return hashes

    def witness_history(self, wl):
        """The history's tree heads by size, once every checkpoint is shown
        cosigned by a pinned key for the witness it names; None otherwise."""
        keys = [(op, k) for op, k in self.witness_keys if k["name"] == wl["witness"]]
        if not keys:
            self.find("witness_log_untrusted",
                      f"no witness key is pinned for {wl['witness']!r}, so its history cannot be told "
                      "from one anybody wrote (pass --witness-key)")
            return None
        if not wl["checkpoints"]:
            self.find("witness_log_untrusted", f"the history of {wl['witness']!r} is empty")
            return None
        vkeys = [k for _, k in keys]
        before = len(self.failures())
        history = {}
        for i, text in enumerate(wl["checkpoints"]):
            try:
                body, sigs = parse_note(text)
                cp = parse_checkpoint(body)
            except ValueError as e:
                self.find("witness_log_untrusted", f"checkpoint {i} of the history is not a checkpoint: {e}")
                continue
            if cp["origin"] != wl["origin"]:
                self.find("witness_log_origin", f"checkpoint {i} of the history is for the log {cp['origin']!r}")
                continue
            try:
                verify_note(body, sigs, vkeys)
            except ValueError:
                self.find("witness_log_untrusted",
                          f"checkpoint {i} of the history (tree size {cp['tree_size']}) is not cosigned "
                          f"by a pinned key for {wl['witness']!r}")
                continue
            size = cp["tree_size"]
            if size in history and history[size] != cp["root"]:
                self.find("witness_log_fork", f"the witness cosigned two roots for tree size {size}")
            history.setdefault(size, cp["root"])
        return history if len(self.failures()) == before else None

    def witness_log(self, b, wl, latest, log_hashes):
        name = "witness log (--witness-log)"
        before = len(self.failures())
        if latest is None:
            self.fail(11, name, "witness_log_mismatch",
                      "the bundle has no latest checkpoint to check the witness's history against")
            return
        if latest["origin"] != wl["origin"]:
            self.fail(11, name, "witness_log_origin",
                      f"the witness log of {wl['witness']!r} is for the log {wl['origin']!r}, and the "
                      f"bundle's checkpoints are from {latest['origin']!r}: the history asked for does not apply")
            return
        history = self.witness_history(wl)
        if history is None:
            self.check(11, name, "fail", "the history is not verifiably the witness's own")
            return
        known = {}
        for a in b["anchors"]:
            cp = a.get("checkpoint_parsed")
            if cp:
                known[cp["tree_size"]] = (cp["root"], f"anchor {a['seq']}")
        known[latest["tree_size"]] = (latest["root"], "the latest checkpoint")
        sizes = sorted(history)
        from_log = prefix_roots(log_hashes, sizes) if log_hashes is not None else None
        largest = sizes[-1]
        linked = history.get(latest["tree_size"]) == latest["root"]
        for i, size in enumerate(sizes):
            ours = known.get(size)
            if ours is None and from_log is not None and from_log[i] is not None:
                ours = (from_log[i], f"the log's first {size} leaves")
            if ours is None:
                continue
            if ours[0] != history[size]:
                self.find("witness_log_fork",
                          f"{ours[1]}: the witness {wl['witness']!r} cosigned another root for tree size "
                          f"{size} (the log showed two histories)")
            elif size == largest:
                linked = True
        for a in b["anchors"]:
            cp = a.get("checkpoint_parsed")
            cosigned = any(w["type"] == "cosignature" and w["name"] == wl["witness"] for w in a["witnesses"])
            if cp and cosigned and cp["tree_size"] not in history:
                self.find("witness_log_mismatch",
                          f"anchor {a['seq']} carries a cosignature from {wl['witness']!r}, but the "
                          "witness's own log does not list it")
        if not linked:
            reach = len(log_hashes) if log_hashes is not None else latest["tree_size"]
            if largest > reach:
                why = (f"the witness has cosigned tree size {largest}, beyond the {reach} leaves the bundle "
                       f"can check, and it did not cosign the bundle's latest checkpoint: pass a --log "
                       f"that reaches tree size {largest}")
            else:
                why = (f"the witness's largest cosigned tree (size {largest}) is not one the bundle "
                       "shows: pass --log to check it against the log's leaves")
            self.find("witness_log_mismatch",
                      f"the bundle's tree cannot be shown to be the one {wl['witness']!r} saw: {why}")
        ok = len(self.failures()) == before
        self.check(11, name, "pass" if ok else "fail",
                   f"{len(wl['checkpoints'])} checkpoint(s) cosigned by {wl['witness']!r} verify with its "
                   f"pinned key, and the bundle's tree is the one it saw, through tree size {largest}"
                   if ok else "the witness's history disagrees with the bundle, or cannot be checked")

    # -- verdict -------------------------------------------------------------------

    def result(self):
        if self.failures():
            verdict, code, anchored = "FAILED", 1, 0
        else:
            independent = [a["entries"] for a in self.anchors if a["independent"]]
            anchored = max(independent) if independent else 0
            # An anchor of no entries commits only to the genesis head every
            # unkeyed journal shares: it anchors no content.
            if anchored == 0:
                verdict, code = "UNANCHORED", 3
            elif anchored >= self.entries:
                verdict, code = "VERIFIED", 0
            else:
                verdict, code = "VERIFIED (PARTIAL)", 2
        self.checks.sort(key=lambda c: c["step"])
        return {"verdict": verdict, "exit": code, "entries": self.entries,
                "anchored_entries": min(anchored, self.entries), "min_operators": self.min,
                "signature": self.signature, "checks": self.checks, "findings": self.findings,
                "anchors": self.anchors}


def vouched_time(witnesses, k):
    """The time k distinct trusted operators vouch for: each operator's
    earliest witness time, and of those the k-th earliest, so no single
    operator can backdate an anchor."""
    per = {}
    for w in witnesses:
        if w["class"] == "trusted" and w["time_ns"] is not None:
            per[w["operator"]] = min(per.get(w["operator"], w["time_ns"]), w["time_ns"])
    times = sorted(per.values())
    return times[k - 1] if len(times) >= k else None


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
    checkpoints = [string(c, "checkpoint") for c in array(doc["checkpoints"], "checkpoints")]
    for i, c in enumerate(checkpoints):
        try:
            parse_note(c)
        except ValueError as e:
            raise Invalid("bundle_schema", f"checkpoint {i}: {e}")
    return {"witness": string(doc["witness"], "witness"), "origin": string(doc["origin"], "origin"),
            "checkpoints": checkpoints}


def read_vkey(value):
    """A vkey given inline, or the path of a file holding one."""
    if "+" in value:
        text = value
    else:
        try:
            with open(value, encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeError) as e:
            raise UsageError(f"cannot read key file {value}: {e}")
    try:
        return parse_vkey(text.strip())
    except ValueError as e:
        raise UsageError(f"{value}: {e}")


def witness_key(value):
    """--witness-key OPERATOR=VKEY, or OPERATOR=HEX for a 32-byte
    cosignature key whose cosigner name is OPERATOR."""
    op, sep, key = value.partition("=")
    if not sep:
        raise UsageError(f"--witness-key takes NAME=VKEY, not {clean(value)!r}")
    if not op.strip():
        raise UsageError("--witness-key needs an operator name before '='")
    if re.fullmatch(r"[0-9a-f]{64}", key):
        try:
            k = make_key(op, TYPE_COSIGNATURE, bytes.fromhex(key))
        except ValueError as e:
            raise UsageError(f"--witness-key {op}: {e}")
    else:
        k = read_vkey(key)
    if k["type"] != TYPE_COSIGNATURE:
        raise UsageError(f"--witness-key {op}: a witness key must be a cosignature/v1 key (type 0x04)")
    return (op, k)


def log_key(value):
    k = read_vkey(value)
    if k["type"] != TYPE_ED25519:
        raise UsageError(f"--log-key {clean(value)}: a log key must be an Ed25519 note key (type 0x01)")
    return k


def print_report(path, r):
    print(f"verify_evidence.py {path}")
    print()
    print(f"  signature  {r['signature']}")
    for c in r["checks"]:
        print(f"  [{c['status']}] {c['step']:>2} {c['name']}: {clean(c['detail'])}")
    for a in r["anchors"]:
        state = "independent" if a["independent"] else ("sound" if a["sound"] else "FAILS ITS CHECKS")
        when = f", no later than {rfc3339(a['time_ns'])}" if a["time_ns"] is not None else ""
        print(f"  anchor {a['seq']}: {a['entries']} entries, {state}, trusted operators: "
              f"{', '.join(a['trusted_operators']) or 'none'}{when}")
        for w in a["witnesses"]:
            label = clean(w.get("label", ""))[:40]
            print(f"    {w['type']:<15} {label:<40} {w['class']:<20} {w['operator'] or ''}")
    shown = [f for f in r["findings"] if f["severity"] != INFO]
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
    p.add_argument("--witness-key", action="append", default=[], metavar="OPERATOR=VKEY")
    p.add_argument("--log-key", action="append", default=[], metavar="VKEY")
    p.add_argument("--min-operators", type=int, default=2)
    p.add_argument("--log", metavar="FILE")
    p.add_argument("--witness-log", action="append", default=[], metavar="FILE")
    p.add_argument("--json", action="store_true", help="print the report as JSON")
    try:
        args = p.parse_args(argv)
    except SystemExit as e:
        return 64 if e.code else 0
    try:
        return run(args)
    except UsageError as e:
        print(f"error: {clean(e)}", file=sys.stderr)
        return 64


def run(args):
    if args.min_operators < 1:
        raise UsageError("--min-operators must be at least 1")
    roots = []
    for v in args.tsa_roots:
        op, sep, path = v.partition("=")
        if not sep or os.path.exists(v):
            op, path = os.path.splitext(os.path.basename(v))[0], v
        if not os.path.isfile(path):
            raise UsageError(f"--tsa-roots: {path} is not a file")
        roots.append((op, path))
    witness_keys = [witness_key(v) for v in args.witness_key]
    log_keys = [log_key(v) for v in args.log_key]
    try:
        log = load_log(args.log) if args.log else None
        wlogs = [load_witness_log(x) for x in args.witness_log]
    except (OSError, Invalid) as e:
        raise UsageError(str(e))
    path = args.bundle
    directory = None
    verifier = Verifier(roots, args.min_operators, log, wlogs, witness_keys, log_keys)
    if os.path.isdir(path):
        directory, path = path, os.path.join(path, "evidence.json")
        try:
            data = read_bundle_file(path)
        except Invalid as e:
            verifier.fail(2, "bundle files", e.code, e.message)
            report = verifier.result()
        else:
            if data is None:
                raise UsageError(f"{directory} is a directory without evidence.json: not a directory bundle")
            report = verifier.run(data, directory)
    else:
        try:
            data = read_file(path)
        except OSError as e:
            raise UsageError(f"cannot read {path}: {e}")
        report = verifier.run(data, directory)
    if args.json:
        print(json.dumps(report, indent=1, default=str))
    else:
        print_report(path, report)
    return report["exit"]


if __name__ == "__main__":
    sys.exit(main())
