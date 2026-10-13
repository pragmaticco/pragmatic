#!/usr/bin/env python3
"""
tsp_ref.py - zero-dependency reference implementation of the RFC 3161
Time-Stamp Protocol client side, written as a template for a Rust port.

Scope
  * build a DER TimeStampReq for a SHA-256 (or SHA-384/512) digest,
    with nonce and certReq
  * POST it to a TSA over HTTP(S) (stdlib urllib only)
  * parse TimeStampResp -> PKIStatusInfo + TimeStampToken (CMS SignedData)
  * extract TSTInfo: version, policy, messageImprint, serialNumber, genTime,
    accuracy, ordering, nonce, tsa (GeneralName)
  * find the signer certificate (sid -> certificates[]) and its subject
  * check the CMS messageDigest signed attribute == H(eContent)
  * check ESS signingCertificate / signingCertificateV2 binds the signer cert
  * verify the signer's signature over the DER SET OF signedAttrs
    (RSA PKCS#1 v1.5 and ECDSA P-256/P-384/P-521, pure Python)

NOT in scope (delegate to `openssl ts -verify` or a vetted X.509 library):
  * X.509 path building / validation to a pinned TSA root, EKU checks,
    revocation. Signature checking here proves "the key in the embedded
    certificate signed this TSTInfo"; only path validation proves that key
    belongs to the TSA you trust.

Usage
  python3 tsp_ref.py request <hexdigest> [--alg sha256] [--nonce-hex HEX] [--no-cert] > req.tsq
  python3 tsp_ref.py fetch <url> <hexdigest> [--out resp.tsr]
  python3 tsp_ref.py parse <resp.tsr> [--digest HEX] [--nonce-hex HEX] [--json]
  python3 tsp_ref.py parse-token <token.tst> ...      (bare ContentInfo, e.g. from openssl -token_out)
"""
import datetime as _dt
import hashlib
import json
import os
import sys
import time
import urllib.request

# ---------------------------------------------------------------------------
# OIDs
# ---------------------------------------------------------------------------
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_SHA1 = "1.3.14.3.2.26"
OID_SHA3_256 = "2.16.840.1.101.3.4.2.8"
HASH_OIDS = {
    "sha256": OID_SHA256, "sha384": OID_SHA384, "sha512": OID_SHA512,
}
OID_TO_HASHLIB = {
    OID_SHA256: "sha256", OID_SHA384: "sha384", OID_SHA512: "sha512",
    OID_SHA1: "sha1", OID_SHA3_256: "sha3_256",
}
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_CT_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_ATTR_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_ATTR_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"      # ESS v1 (SHA-1 cert hash)
OID_ATTR_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"   # ESS v2 (default SHA-256)

OID_RSA = "1.2.840.113549.1.1.1"
OID_RSA_SHA256 = "1.2.840.113549.1.1.11"
OID_RSA_SHA384 = "1.2.840.113549.1.1.12"
OID_RSA_SHA512 = "1.2.840.113549.1.1.13"
OID_RSA_SHA1 = "1.2.840.113549.1.1.5"
OID_RSA_PSS = "1.2.840.113549.1.1.10"
OID_EC_PUBKEY = "1.2.840.10045.2.1"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3"
OID_ECDSA_SHA512 = "1.2.840.10045.4.3.4"
OID_P256 = "1.2.840.10045.3.1.7"
OID_P384 = "1.3.132.0.34"
OID_P521 = "1.3.132.0.35"

ATTR_NAMES = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber",
    "2.5.4.13": "description", "2.5.4.97": "organizationIdentifier",
    "1.2.840.113549.1.9.1": "emailAddress",
}

# ---------------------------------------------------------------------------
# DER encoding (only what TimeStampReq needs)
# ---------------------------------------------------------------------------

def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + der_len(len(value)) + value


def der_int(v: int) -> bytes:
    """Minimal two's-complement INTEGER (non-negative values only here)."""
    if v < 0:
        raise ValueError("negative INTEGER not needed")
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b          # keep it positive
    return der_tlv(0x02, b)


def der_oid(dotted: str) -> bytes:
    arcs = [int(x) for x in dotted.split(".")]
    body = bytearray([40 * arcs[0] + arcs[1]])
    for a in arcs[2:]:
        chunk = [a & 0x7F]
        a >>= 7
        while a:
            chunk.append(0x80 | (a & 0x7F))
            a >>= 7
        body += bytes(reversed(chunk))
    return der_tlv(0x06, bytes(body))


def der_seq(*items: bytes) -> bytes:
    return der_tlv(0x30, b"".join(items))


DER_NULL = b"\x05\x00"
DER_TRUE = b"\x01\x01\xff"

# Fixed 69-byte layout for SHA-256 + 8-byte nonce (top byte 0x40..0x7f) + certReq TRUE.
# Byte-identical to `openssl ts -query -digest <hex> -sha256 -cert` for the same nonce.
#   off len  bytes
#    0   2   30 43                          SEQUENCE TimeStampReq, 67 content bytes
#    2   3   02 01 01                       version = 1
#    5   2   30 31                          SEQUENCE MessageImprint (49)
#    7   2   30 0d                            SEQUENCE AlgorithmIdentifier (13)
#    9  11   06 09 60 86 48 01 65 03 04 02 01   OID 2.16.840.1.101.3.4.2.1 (sha256)
#   20   2   05 00                              NULL parameters
#   22   2   04 20                            OCTET STRING (32) hashedMessage
#   24  32   <digest>
#   56   2   02 08                          INTEGER nonce (8 bytes; prefix 00 + len 09 if top bit set)
#   58   8   <nonce>
#   66   3   01 01 ff                       BOOLEAN certReq = TRUE (omit entirely for FALSE)
# Without nonce: 30 39 ... (59 bytes); without certReq: 30 40 ... (66 bytes).
TSQ_SHA256_PREFIX = bytes.fromhex("3043020101303130 0d060960864801650304020105000420".replace(" ", ""))


def build_timestamp_req(digest: bytes, alg: str = "sha256", nonce: int | None = None,
                        cert_req: bool = True, policy_oid: str | None = None) -> bytes:
    """
    TimeStampReq ::= SEQUENCE {
       version        INTEGER { v1(1) },
       messageImprint MessageImprint,
       reqPolicy      TSAPolicyId           OPTIONAL,
       nonce          INTEGER               OPTIONAL,
       certReq        BOOLEAN DEFAULT FALSE,
       extensions     [0] IMPLICIT Extensions OPTIONAL }
    MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
    DER rule: a BOOLEAN equal to its DEFAULT must be omitted -> certReq FALSE is absent.
    """
    expected = {"sha256": 32, "sha384": 48, "sha512": 64}[alg]
    if len(digest) != expected:
        raise ValueError(f"{alg} digest must be {expected} bytes")
    # AlgorithmIdentifier with explicit NULL parameters: that is what openssl
    # emits, and every TSA tested accepts it (RFC 5754 permits absent too).
    alg_id = der_seq(der_oid(HASH_OIDS[alg]), DER_NULL)
    parts = [der_int(1), der_seq(alg_id, der_tlv(0x04, digest))]
    if policy_oid:
        parts.append(der_oid(policy_oid))
    if nonce is not None:
        parts.append(der_int(nonce))
    if cert_req:
        parts.append(DER_TRUE)
    return der_seq(*parts)


def fresh_nonce() -> int:
    """64-bit nonce with top byte in 0x40..0x7f so the DER encoding is always
    exactly 02 08 xx*8 (fixed 69-byte request for SHA-256 + certReq)."""
    b = bytearray(os.urandom(8))
    b[0] = 0x40 | (b[0] & 0x3F)
    return int.from_bytes(b, "big")


# ---------------------------------------------------------------------------
# DER decoding: a strict-enough TLV reader
# ---------------------------------------------------------------------------

class TLV:
    __slots__ = ("tag", "start", "hdr_len", "length", "buf")

    def __init__(self, buf, start, tag, hdr_len, length):
        self.buf, self.start, self.tag, self.hdr_len, self.length = buf, start, tag, hdr_len, length

    @property
    def value(self) -> bytes:
        s = self.start + self.hdr_len
        return bytes(self.buf[s:s + self.length])

    @property
    def raw(self) -> bytes:
        """Full encoding (tag+len+value) - needed for hashing certs and signedAttrs."""
        return bytes(self.buf[self.start:self.start + self.hdr_len + self.length])

    @property
    def end(self) -> int:
        return self.start + self.hdr_len + self.length

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self):
        if not self.constructed:
            raise ValueError(f"tag 0x{self.tag:02x} is primitive")
        pos, end = self.start + self.hdr_len, self.end
        out = []
        while pos < end:
            t = read_tlv(self.buf, pos)
            if t.end > end:
                raise ValueError("child overruns parent")
            out.append(t)
            pos = t.end
        return out


def read_tlv(buf, pos: int) -> TLV:
    if pos + 2 > len(buf):
        raise ValueError("truncated TLV header")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise ValueError("high-tag-number form not used by RFC 3161")
    first = buf[pos + 1]
    if first < 0x80:
        length, hdr = first, 2
    elif first == 0x80:
        raise ValueError("indefinite length is BER, not DER")
    else:
        n = first & 0x7F
        if n > 4 or pos + 2 + n > len(buf):
            raise ValueError("bad long-form length")
        length = int.from_bytes(buf[pos + 2:pos + 2 + n], "big")
        hdr = 2 + n
    if pos + hdr + length > len(buf):
        raise ValueError("TLV value truncated")
    return TLV(buf, pos, tag, hdr, length)


def parse_der(data: bytes) -> TLV:
    t = read_tlv(data, 0)
    if t.end != len(data):
        raise ValueError(f"{len(data) - t.end} trailing bytes after DER object")
    return t


def expect(t: TLV, tag: int, what: str) -> TLV:
    if t.tag != tag:
        raise ValueError(f"{what}: expected tag 0x{tag:02x}, got 0x{t.tag:02x}")
    return t


def dec_int(t: TLV) -> int:
    expect(t, 0x02, "INTEGER")
    return int.from_bytes(t.value, "big", signed=True)


def dec_oid(t: TLV) -> str:
    expect(t, 0x06, "OID")
    v = t.value
    arcs, acc = [], 0
    for b in v:
        acc = (acc << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(acc)
            acc = 0
    first = arcs[0]
    head = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    return ".".join(str(x) for x in head + arcs[1:])


def dec_string(t: TLV) -> str:
    # UTF8String 0x0c, PrintableString 0x13, IA5String 0x16, T61 0x14, BMP 0x1e
    if t.tag == 0x1E:
        return t.value.decode("utf-16-be")
    return t.value.decode("utf-8", errors="replace")


def dec_name(t: TLV) -> str:
    """X.501 Name (SEQUENCE OF RDN SET OF AttributeTypeAndValue) -> 'C=..., O=..., CN=...'"""
    expect(t, 0x30, "Name")
    parts = []
    for rdn in t.children():
        for atv in expect(rdn, 0x31, "RDN").children():
            oid_t, val_t = atv.children()
            oid = dec_oid(oid_t)
            parts.append(f"{ATTR_NAMES.get(oid, oid)}={dec_string(val_t)}")
    return ", ".join(parts)


def dec_generalized_time(t: TLV) -> _dt.datetime:
    """GeneralizedTime YYYYMMDDHHMMSS[.f+]Z (RFC 3161 2.4.2: UTC, 'Z', no trailing zeros in fraction)."""
    expect(t, 0x18, "GeneralizedTime")
    s = t.value.decode("ascii")
    if not s.endswith("Z"):
        raise ValueError("genTime must be UTC (Z)")
    body = s[:-1]
    frac = ""
    if "." in body:
        body, frac = body.split(".", 1)
    dt = _dt.datetime.strptime(body, "%Y%m%d%H%M%S").replace(tzinfo=_dt.timezone.utc)
    if frac:
        dt = dt.replace(microsecond=int((frac + "000000")[:6]))
    return dt


def dec_utc_time(t: TLV) -> _dt.datetime:
    expect(t, 0x17, "UTCTime")
    s = t.value.decode("ascii")
    dt = _dt.datetime.strptime(s, "%y%m%d%H%M%SZ")
    return dt.replace(tzinfo=_dt.timezone.utc)


# ---------------------------------------------------------------------------
# TimeStampResp / CMS / TSTInfo parsing
# ---------------------------------------------------------------------------
PKI_STATUS = {0: "granted", 1: "grantedWithMods", 2: "rejection", 3: "waiting",
              4: "revocationWarning", 5: "revocationNotification"}
FAIL_BITS = {0: "badAlg", 2: "badRequest", 5: "badDataFormat", 14: "timeNotAvailable",
             15: "unacceptedPolicy", 16: "unacceptedExtension", 17: "addInfoNotAvailable",
             25: "systemFailure"}


def parse_timestamp_resp(data: bytes) -> dict:
    """
    TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken TimeStampToken OPTIONAL }
    PKIStatusInfo ::= SEQUENCE { status INTEGER, statusString PKIFreeText OPTIONAL,
                                 failInfo PKIFailureInfo OPTIONAL }
    """
    top = expect(parse_der(data), 0x30, "TimeStampResp")
    kids = top.children()
    si = expect(kids[0], 0x30, "PKIStatusInfo").children()
    status = dec_int(si[0])
    out = {"status": status, "status_name": PKI_STATUS.get(status, "?"),
           "status_strings": [], "fail_info": []}
    for x in si[1:]:
        if x.tag == 0x30:     # PKIFreeText ::= SEQUENCE OF UTF8String
            out["status_strings"] = [dec_string(s) for s in x.children()]
        elif x.tag == 0x03:   # BIT STRING
            v = x.value
            bits = int.from_bytes(v[1:], "big") if len(v) > 1 else 0
            nbits = 8 * (len(v) - 1)
            out["fail_info"] = [FAIL_BITS.get(i, str(i)) for i in range(nbits)
                                if bits >> (nbits - 1 - i) & 1]
    if status not in (0, 1):
        return out
    if len(kids) < 2:
        raise ValueError("granted status but no timeStampToken")
    out["token_der"] = kids[1].raw
    out.update(parse_token(kids[1]))
    return out


def parse_token(ci: TLV) -> dict:
    """
    TimeStampToken ::= ContentInfo
    ContentInfo ::= SEQUENCE { contentType OID(signedData), content [0] EXPLICIT SignedData }
    SignedData ::= SEQUENCE {
        version CMSVersion, digestAlgorithms SET OF AlgorithmIdentifier,
        encapContentInfo EncapsulatedContentInfo,
        certificates [0] IMPLICIT CertificateSet OPTIONAL,
        crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
        signerInfos SET OF SignerInfo }
    EncapsulatedContentInfo ::= SEQUENCE { eContentType OID(id-ct-TSTInfo),
                                           eContent [0] EXPLICIT OCTET STRING }
    """
    ct, content = expect(ci, 0x30, "ContentInfo").children()
    if dec_oid(ct) != OID_SIGNED_DATA:
        raise ValueError("token is not CMS SignedData")
    sd = expect(expect(content, 0xA0, "[0] content").children()[0], 0x30, "SignedData")
    sdk = sd.children()
    idx = 2
    eci = expect(sdk[idx], 0x30, "EncapsulatedContentInfo").children()
    if dec_oid(eci[0]) != OID_CT_TSTINFO:
        raise ValueError("eContentType is not id-ct-TSTInfo")
    econtent_os = expect(expect(eci[1], 0xA0, "[0] eContent").children()[0], 0x04, "eContent OCTET STRING")
    tstinfo_der = econtent_os.value
    idx += 1
    certs = []
    if idx < len(sdk) and sdk[idx].tag == 0xA0:
        certs = [parse_cert(c) for c in sdk[idx].children() if c.tag == 0x30]
        idx += 1
    if idx < len(sdk) and sdk[idx].tag == 0xA1:
        idx += 1
    signer_infos = expect(sdk[idx], 0x31, "signerInfos").children()
    if len(signer_infos) != 1:
        raise ValueError("RFC 3161 tokens carry exactly one SignerInfo")
    out = {"tstinfo_der": tstinfo_der, "tstinfo": parse_tstinfo(tstinfo_der),
           "certificates": [{"subject": c["subject"], "issuer": c["issuer"],
                             "serial_hex": f"{c['serial']:x}",
                             "sha256": hashlib.sha256(c["der"]).hexdigest()} for c in certs]}
    out["signer"] = check_signer(signer_infos[0], certs, tstinfo_der)
    return out


def parse_tstinfo(der: bytes) -> dict:
    """
    TSTInfo ::= SEQUENCE {
       version        INTEGER { v1(1) },
       policy         TSAPolicyId,                -- OID
       messageImprint MessageImprint,
       serialNumber   INTEGER,                    -- up to 160 bits
       genTime        GeneralizedTime,
       accuracy       Accuracy                OPTIONAL,  -- SEQUENCE
       ordering       BOOLEAN DEFAULT FALSE,             -- 01
       nonce          INTEGER                 OPTIONAL,  -- 02
       tsa            [0] GeneralName         OPTIONAL,  -- A0 (explicit: CHOICE)
       extensions     [1] IMPLICIT Extensions OPTIONAL } -- A1
    Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] INTEGER OPTIONAL,
                            micros [1] INTEGER OPTIONAL }   -- [0]/[1] IMPLICIT -> 80/81
    """
    kids = expect(parse_der(der), 0x30, "TSTInfo").children()
    mi = kids[2].children()
    alg = mi[0].children()
    info = {
        "version": dec_int(kids[0]),
        "policy": dec_oid(kids[1]),
        "hash_alg": dec_oid(alg[0]),
        "hashed_message_hex": expect(mi[1], 0x04, "hashedMessage").value.hex(),
        "serial_number": dec_int(kids[3]),
        "gen_time": dec_generalized_time(kids[4]).isoformat(),
        "gen_time_raw": kids[4].value.decode(),
        "accuracy": None, "ordering": False, "nonce": None, "tsa": None,
    }
    info["serial_hex"] = f"{info['serial_number']:x}"
    for k in kids[5:]:
        if k.tag == 0x30:
            acc = {}
            for a in k.children():
                key = {0x02: "seconds", 0x80: "millis", 0x81: "micros"}[a.tag]
                acc[key] = int.from_bytes(a.value, "big")
            info["accuracy"] = acc
        elif k.tag == 0x01:
            info["ordering"] = k.value != b"\x00"
        elif k.tag == 0x02:
            info["nonce"] = dec_int(k)
        elif k.tag == 0xA0:
            info["tsa"] = dec_general_name(k.children()[0])
        elif k.tag == 0xA1:
            info["extensions_present"] = True
    if info["nonce"] is not None:
        info["nonce_hex"] = f"{info['nonce']:x}"
    return info


def dec_general_name(g: TLV) -> str:
    # GeneralName CHOICE; [4] directoryName is EXPLICIT because Name is a CHOICE
    if g.tag == 0xA4:
        return "DirName:" + dec_name(g.children()[0])
    if g.tag in (0x81, 0x82, 0x86):   # rfc822Name, dNSName, URI (IA5String, implicit)
        return {0x81: "email:", 0x82: "DNS:", 0x86: "URI:"}[g.tag] + g.value.decode()
    return f"[tag 0x{g.tag:02x}]"


# ---------------------------------------------------------------------------
# Certificates (just enough to find the signer and its public key)
# ---------------------------------------------------------------------------

def parse_cert(c: TLV) -> dict:
    tbs, sig_alg, sig = c.children()
    t = tbs.children()
    i = 0
    if t[0].tag == 0xA0:     # [0] EXPLICIT version
        i = 1
    serial = dec_int(t[i])
    issuer = t[i + 2]
    validity = t[i + 3].children()
    subject = t[i + 4]
    spki = t[i + 5]

    def any_time(x):
        return dec_utc_time(x) if x.tag == 0x17 else dec_generalized_time(x)

    return {"der": c.raw, "serial": serial, "issuer_der": issuer.raw,
            "issuer": dec_name(issuer), "subject": dec_name(subject),
            "not_before": any_time(validity[0]), "not_after": any_time(validity[1]),
            "spki": spki}


def check_signer(si: TLV, certs: list, tstinfo_der: bytes) -> dict:
    """
    SignerInfo ::= SEQUENCE {
       version, sid SignerIdentifier, digestAlgorithm,
       signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
       signatureAlgorithm, signature OCTET STRING, unsignedAttrs [1] OPTIONAL }
    The signature is computed over the DER of signedAttrs re-tagged as
    SET OF (0x31), not over the [0] (0xA0) bytes as they appear in the token.
    """
    k = si.children()
    sid = k[1]
    signer = None
    if sid.tag == 0x30:                 # issuerAndSerialNumber
        iss, ser = sid.children()
        for c in certs:
            if c["issuer_der"] == iss.raw and c["serial"] == dec_int(ser):
                signer = c
    elif sid.tag == 0x80:               # [0] subjectKeyIdentifier (rare for TSAs)
        pass
    dig_oid = dec_oid(k[2].children()[0])
    attrs_t = expect(k[3], 0xA0, "signedAttrs")
    sig_alg = dec_oid(k[4].children()[0])
    signature = expect(k[5], 0x04, "signature").value
    attrs = {}
    for a in attrs_t.children():
        oid_t, vals = a.children()
        attrs[dec_oid(oid_t)] = vals.children()[0]
    h = hashlib.new(OID_TO_HASHLIB[dig_oid])
    h.update(tstinfo_der)
    md_ok = attrs[OID_ATTR_MESSAGE_DIGEST].value == h.digest()
    ct_ok = dec_oid(attrs[OID_ATTR_CONTENT_TYPE]) == OID_CT_TSTINFO
    res = {"digest_alg": OID_TO_HASHLIB.get(dig_oid, dig_oid), "signature_alg": sig_alg,
           "message_digest_ok": md_ok, "content_type_ok": ct_ok,
           "signer_subject": signer["subject"] if signer else None,
           "signer_cert_sha256": hashlib.sha256(signer["der"]).hexdigest() if signer else None,
           "signer_not_after": signer["not_after"].isoformat() if signer else None}
    # ESS binding of the signer certificate (RFC 2634 / RFC 5035)
    ess_ok = None
    if signer:
        if OID_ATTR_SIGNING_CERT_V2 in attrs:
            first = attrs[OID_ATTR_SIGNING_CERT_V2].children()[0].children()[0]
            parts = first.children()
            halg = "sha256"
            if parts[0].tag == 0x30:     # optional hashAlgorithm (DEFAULT sha256)
                halg = OID_TO_HASHLIB[dec_oid(parts[0].children()[0])]
                parts = parts[1:]
            ess_ok = parts[0].value == hashlib.new(halg, signer["der"]).digest()
            res["ess"] = "signingCertificateV2/" + halg
        elif OID_ATTR_SIGNING_CERT in attrs:
            first = attrs[OID_ATTR_SIGNING_CERT].children()[0].children()[0]
            ess_ok = first.children()[0].value == hashlib.sha1(signer["der"]).digest()
            res["ess"] = "signingCertificate/sha1"
    res["ess_cert_ok"] = ess_ok
    if OID_ATTR_SIGNING_TIME in attrs:
        st = attrs[OID_ATTR_SIGNING_TIME]
        res["signing_time"] = (dec_utc_time(st) if st.tag == 0x17 else dec_generalized_time(st)).isoformat()
    # Signature over SET OF signedAttrs
    signed_bytes = b"\x31" + attrs_t.raw[1:]
    if signer:
        try:
            res["signature_ok"] = verify_signature(signer["spki"], sig_alg, dig_oid, signed_bytes, signature)
        except NotImplementedError as e:
            res["signature_ok"] = None
            res["signature_note"] = str(e)
    return res


# ---------------------------------------------------------------------------
# Signature verification (pure Python; constant-time not required for verify)
# ---------------------------------------------------------------------------
DIGEST_INFO_PREFIX = {  # DER DigestInfo prefixes for PKCS#1 v1.5 (RFC 8017 9.2 note 1)
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}
SIG_HASH = {OID_RSA_SHA256: "sha256", OID_RSA_SHA384: "sha384", OID_RSA_SHA512: "sha512",
            OID_RSA_SHA1: "sha1", OID_ECDSA_SHA256: "sha256", OID_ECDSA_SHA384: "sha384",
            OID_ECDSA_SHA512: "sha512"}

CURVES = {  # (p, a, b, Gx, Gy, n)
    OID_P256: (0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
               -3,
               0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
               0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
               0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
               0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551),
    OID_P384: (int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16),
               -3,
               int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16),
               int("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16),
               int("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16),
               int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)),
    OID_P521: ((1 << 521) - 1, -3,
               int("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16),
               int("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16),
               int("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16),
               int("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 16)),
}


def _ec_add(P, Q, p, a):
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
        return None
    if P == Q:
        lam = (3 * P[0] * P[0] + a) * pow(2 * P[1], -1, p) % p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    return (x, (lam * (P[0] - x) - P[1]) % p)


def _ec_mul(k, P, p, a):
    R = None
    while k:
        if k & 1:
            R = _ec_add(R, P, p, a)
        P = _ec_add(P, P, p, a)
        k >>= 1
    return R


def verify_signature(spki: TLV, sig_alg: str, digest_oid: str, msg: bytes, sig: bytes) -> bool:
    alg_t, key_bits = spki.children()
    alg_kids = alg_t.children()
    key_alg = dec_oid(alg_kids[0])
    pub = expect(key_bits, 0x03, "subjectPublicKey").value[1:]   # skip unused-bits byte
    if key_alg == OID_RSA:
        if sig_alg == OID_RSA_PSS:
            raise NotImplementedError("RSASSA-PSS not implemented in reference")
        hname = SIG_HASH.get(sig_alg) or OID_TO_HASHLIB[digest_oid]   # bare rsaEncryption -> use digestAlgorithm
        n_t, e_t = parse_der(pub).children()
        n, e = dec_int(n_t), dec_int(e_t)
        k = (n.bit_length() + 7) // 8
        em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
        t = DIGEST_INFO_PREFIX[hname] + hashlib.new(hname, msg).digest()
        expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
        return em == expected
    if key_alg == OID_EC_PUBKEY:
        curve = dec_oid(alg_kids[1])
        if curve not in CURVES:
            raise NotImplementedError(f"curve {curve}")
        p, a, b, gx, gy, n = CURVES[curve]
        if pub[0] != 0x04:
            raise NotImplementedError("compressed EC point")
        L = (len(pub) - 1) // 2
        Q = (int.from_bytes(pub[1:1 + L], "big"), int.from_bytes(pub[1 + L:], "big"))
        r_t, s_t = parse_der(sig).children()
        r, s = dec_int(r_t), dec_int(s_t)
        if not (1 <= r < n and 1 <= s < n):
            return False
        hname = SIG_HASH[sig_alg]
        e = int.from_bytes(hashlib.new(hname, msg).digest(), "big")
        hb = hashlib.new(hname).digest_size * 8
        if hb > n.bit_length():
            e >>= hb - n.bit_length()
        w = pow(s, -1, n)
        X = _ec_add(_ec_mul(e * w % n, (gx, gy), p, a), _ec_mul(r * w % n, Q, p, a), p, a)
        return X is not None and X[0] % n == r
    raise NotImplementedError(f"key algorithm {key_alg}")


# ---------------------------------------------------------------------------
# Checks a client MUST do before accepting a token (RFC 3161 2.4.2)
# ---------------------------------------------------------------------------

def check_against_request(parsed: dict, digest: bytes | None, nonce: int | None) -> list:
    problems = []
    if parsed["status"] not in (0, 1):
        return [f"status {parsed['status_name']} {parsed['fail_info']} {parsed['status_strings']}"]
    t = parsed["tstinfo"]
    if digest is not None and t["hashed_message_hex"] != digest.hex():
        problems.append("messageImprint mismatch")
    if nonce is not None and t["nonce"] != nonce:
        problems.append("nonce mismatch")
    s = parsed["signer"]
    for k in ("message_digest_ok", "content_type_ok", "ess_cert_ok", "signature_ok"):
        if s.get(k) is False:
            problems.append(f"{k} is False")
    return problems


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _post(url: str, req: bytes, timeout: float = 20.0) -> tuple:
    r = urllib.request.Request(url, data=req, method="POST",
                               headers={"Content-Type": "application/timestamp-query",
                                        "User-Agent": "pragmatic-tsp-ref/0.1"})
    t0 = time.monotonic()
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        body = resp.read()
        ctype = resp.headers.get("Content-Type")
    return body, ctype, time.monotonic() - t0


def _arg(argv, name, default=None):
    if name in argv:
        i = argv.index(name)
        return argv[i + 1]
    return default


def _jsonable(d):
    return {k: (v.hex() if isinstance(v, bytes) else v) for k, v in d.items()
            if k not in ("token_der", "tstinfo_der")}


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "request":
        digest = bytes.fromhex(argv[2])
        alg = _arg(argv, "--alg", "sha256")
        nh = _arg(argv, "--nonce-hex")
        nonce = int(nh, 16) if nh else fresh_nonce()
        req = build_timestamp_req(digest, alg, nonce, cert_req="--no-cert" not in argv)
        sys.stderr.write(f"nonce=0x{nonce:x} len={len(req)}\n")
        sys.stdout.buffer.write(req)
        return 0
    if cmd == "fetch":
        url, digest = argv[2], bytes.fromhex(argv[3])
        alg = {32: "sha256", 48: "sha384", 64: "sha512"}[len(digest)]
        nonce = fresh_nonce()
        req = build_timestamp_req(digest, alg, nonce, cert_req=True)
        body, ctype, dt = _post(url, req)
        out = _arg(argv, "--out")
        if out:
            open(out, "wb").write(body)
        parsed = parse_timestamp_resp(body)
        problems = check_against_request(parsed, digest, nonce)
        print(json.dumps({"url": url, "content_type": ctype, "bytes": len(body),
                          "latency_ms": round(dt * 1000, 1), "problems": problems,
                          **_jsonable(parsed)}, indent=2, default=str))
        return 1 if problems else 0
    if cmd in ("parse", "parse-token"):
        data = open(argv[2], "rb").read()
        if cmd == "parse":
            parsed = parse_timestamp_resp(data)
        else:
            parsed = {"status": 0, "status_name": "granted(token)", "fail_info": [], "status_strings": []}
            parsed.update(parse_token(parse_der(data)))
        dh = _arg(argv, "--digest")
        nh = _arg(argv, "--nonce-hex")
        problems = check_against_request(parsed, bytes.fromhex(dh) if dh else None,
                                         int(nh, 16) if nh else None)
        if "--json" in argv:
            print(json.dumps({"problems": problems, **_jsonable(parsed)}, indent=2, default=str))
        else:
            t = parsed.get("tstinfo", {})
            s = parsed.get("signer", {})
            print(f"status        : {parsed['status_name']} {parsed['fail_info'] or ''}")
            if t:
                print(f"genTime       : {t['gen_time']}  (raw {t['gen_time_raw']})")
                print(f"messageImprint: {OID_TO_HASHLIB.get(t['hash_alg'], t['hash_alg'])}:{t['hashed_message_hex']}")
                print(f"serialNumber  : 0x{t['serial_hex']}")
                print(f"policy        : {t['policy']}")
                print(f"nonce         : {('0x' + t['nonce_hex']) if t['nonce'] is not None else None}")
                print(f"accuracy      : {t['accuracy']}  ordering={t['ordering']}")
                print(f"tsa (TSTInfo) : {t['tsa']}")
                print(f"signer cert   : {s.get('signer_subject')}")
                print(f"sig/digest    : {s.get('signature_alg')} / {s.get('digest_alg')}  ess={s.get('ess')}")
                print(f"checks        : messageDigest={s.get('message_digest_ok')} ess={s.get('ess_cert_ok')} "
                      f"signature={s.get('signature_ok')} contentType={s.get('content_type_ok')}")
            print(f"problems      : {problems or 'none'}")
        return 1 if problems else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
