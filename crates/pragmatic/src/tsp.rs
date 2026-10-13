//! RFC 3161 Time-Stamp Protocol: build requests, parse responses and
//! tokens. No signature verification.
//!
//! Pragmatic Server anchors each batch's Merkle root with one or more
//! public Time-Stamp Authorities, and evidence bundles carry the resulting
//! tokens so an auditor can prove the journal existed no later than the
//! TSA's clock says. This module covers the parts of that exchange that
//! must live in the zero-dependency core:
//!
//! - [`request`] builds the DER `TimeStampReq` for a SHA-256 digest, a
//!   64-bit nonce and `certReq = true`. The bytes are identical to what
//!   `openssl ts -query -digest <hex> -sha256 -cert` produces for the same
//!   nonce, including the explicit `NULL` algorithm parameters OpenSSL
//!   writes, so every TSA that accepts OpenSSL's requests accepts ours.
//! - [`parse_response`] reads a `TimeStampResp`: the PKI status, its
//!   free-text and failure bits, and the token (a CMS `ContentInfo`) as
//!   bytes, ready to store.
//! - [`parse_token`] walks `ContentInfo -> SignedData ->
//!   EncapsulatedContentInfo -> TSTInfo` and returns the fields a verifier
//!   checks: policy, message imprint, serial number, `genTime`, accuracy,
//!   ordering, nonce and TSA name.
//!
//! **Signatures are not verified here.** Checking a CMS signature means
//! X.509 path building, revocation and several signature algorithms, which
//! is OpenSSL's job (`openssl ts -verify`), and the server and the CLI
//! delegate to it. What this module guarantees is that a token's claimed
//! contents are read exactly and that malformed input is rejected, never
//! a panic.
//!
//! # Strict DER
//!
//! Tokens are adversarial input that will later be handed to other parsers
//! (OpenSSL, auditors' tools), so the reader accepts DER only: definite
//! lengths in minimal form, lengths that fit the input, minimal INTEGERs,
//! primitive strings, single-byte tags, and nesting no deeper than
//! [`MAX_DEPTH`]. Every response and token is checked as a whole before
//! any field is read, so even the parts this module does not interpret
//! (certificates, signer infos) must be well-formed. Rejecting BER that a
//! lenient parser would accept narrows the room for two parsers to
//! disagree about what the same bytes say. Responses from every public TSA
//! tried so far are strict DER.

use std::fmt;

/// Deepest nesting of constructed elements accepted. Responses from
/// public TSAs nest up to 20 levels (names inside certificates and signed
/// attributes, inside signed data, inside the response); the margin leaves
/// room for whole tokens embedded in unsigned attributes, while still
/// bounding recursion on hostile input.
pub const MAX_DEPTH: usize = 64;

/// OID of SHA-256 (NIST hash algorithms, RFC 5754).
pub const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
/// OID of CMS `signedData` (RFC 5652).
pub const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
/// OID of `id-ct-TSTInfo`, the content type of a time-stamp token
/// (RFC 3161 section 2.4.2).
pub const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";

/// Encoded content octets of [`OID_SHA256`].
const SHA256_OID_DER: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0c;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
/// `[0]` and `[1]`, primitive (IMPLICIT INTEGERs in `Accuracy`).
const TAG_CTX0_PRIM: u8 = 0x80;
const TAG_CTX1_PRIM: u8 = 0x81;
/// `[0]` and `[1]`, constructed (EXPLICIT wrappers, IMPLICIT sequences).
const TAG_CTX0: u8 = 0xa0;
const TAG_CTX1: u8 = 0xa1;

/// Bits of `PKIFailureInfo` (RFC 3161 section 2.4.2), as set in
/// [`Response::fail_info`]: bit `n` of the ASN.1 BIT STRING is `1 << n`.
pub mod fail_info {
    /// Unrecognized or unsupported algorithm identifier.
    pub const BAD_ALG: u32 = 1 << 0;
    /// Transaction not permitted or supported.
    pub const BAD_REQUEST: u32 = 1 << 2;
    /// The data submitted has the wrong format.
    pub const BAD_DATA_FORMAT: u32 = 1 << 5;
    /// The TSA's time source is not available.
    pub const TIME_NOT_AVAILABLE: u32 = 1 << 14;
    /// The requested TSA policy is not supported by the TSA.
    pub const UNACCEPTED_POLICY: u32 = 1 << 15;
    /// The requested extension is not supported by the TSA.
    pub const UNACCEPTED_EXTENSION: u32 = 1 << 16;
    /// The additional information requested could not be understood or is
    /// not available.
    pub const ADD_INFO_NOT_AVAILABLE: u32 = 1 << 17;
    /// The request cannot be handled due to system failure.
    pub const SYSTEM_FAILURE: u32 = 1 << 25;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a response or token was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TspError {
    /// The input ends inside an element, or a length points past the end.
    Truncated,
    /// The bytes are not DER (indefinite or non-minimal length, non-minimal
    /// integer, constructed string, multi-byte tag, ...).
    NotDer(&'static str),
    /// Elements are nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A required element is missing.
    Missing(&'static str),
    /// An element has the wrong tag for its place in the structure.
    UnexpectedTag {
        field: &'static str,
        expected: u8,
        found: u8,
    },
    /// Elements or bytes follow a complete structure.
    TrailingData(&'static str),
    /// Well-formed DER whose content breaks RFC 3161 or CMS rules.
    Invalid(&'static str),
}

impl fmt::Display for TspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TspError::Truncated => f.write_str("truncated DER"),
            TspError::NotDer(why) => write!(f, "not DER: {why}"),
            TspError::TooDeep => write!(f, "DER nested deeper than {MAX_DEPTH} levels"),
            TspError::Missing(field) => write!(f, "missing {field}"),
            TspError::UnexpectedTag {
                field,
                expected,
                found,
            } => write!(
                f,
                "{field}: expected tag {expected:#04x}, found {found:#04x}"
            ),
            TspError::TrailingData(after) => write!(f, "unexpected data after {after}"),
            TspError::Invalid(why) => write!(f, "invalid time-stamp data: {why}"),
        }
    }
}

impl std::error::Error for TspError {}

// ---------------------------------------------------------------------------
// DER reading
// ---------------------------------------------------------------------------

/// One decoded element.
#[derive(Clone, Copy, Debug)]
struct Tlv<'a> {
    tag: u8,
    /// The content octets.
    value: &'a [u8],
    /// The whole encoding: tag, length and content.
    raw: &'a [u8],
}

/// Read one element from the front of `input`; return it and what follows.
fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), TspError> {
    let (&tag, after_tag) = input.split_first().ok_or(TspError::Truncated)?;
    if tag & 0x1f == 0x1f {
        return Err(TspError::NotDer("multi-byte tag"));
    }
    let (&first, mut rest) = after_tag.split_first().ok_or(TspError::Truncated)?;
    let len = match first {
        0x00..=0x7f => first as usize,
        0x80 => return Err(TspError::NotDer("indefinite length")),
        _ => {
            let count = (first & 0x7f) as usize;
            // Four length octets already allow 4 GiB, far beyond any token,
            // and keep the arithmetic below inside a 32-bit usize.
            if count > 4 {
                return Err(TspError::NotDer("length longer than four octets"));
            }
            if rest.len() < count {
                return Err(TspError::Truncated);
            }
            let (octets, after) = rest.split_at(count);
            if octets[0] == 0 {
                return Err(TspError::NotDer("length with leading zero octet"));
            }
            let len = octets
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | b as usize);
            if len < 0x80 {
                return Err(TspError::NotDer("long-form length below 128"));
            }
            rest = after;
            len
        }
    };
    if len > rest.len() {
        return Err(TspError::Truncated);
    }
    let header = input.len() - rest.len();
    let (value, after) = rest.split_at(len);
    let tlv = Tlv {
        tag,
        value,
        raw: &input[..header + len],
    };
    Ok((tlv, after))
}

/// Check that `input` is a sequence of well-formed DER elements, recursing
/// into every constructed element.
fn check_der(mut input: &[u8], depth: usize) -> Result<(), TspError> {
    if depth > MAX_DEPTH {
        return Err(TspError::TooDeep);
    }
    while !input.is_empty() {
        let (tlv, rest) = read_tlv(input)?;
        let constructed = tlv.tag & 0x20 != 0;
        let universal = tlv.tag & 0xc0 == 0;
        if tlv.tag == 0 {
            return Err(TspError::NotDer("end-of-contents marker"));
        }
        if universal && constructed && tlv.tag != TAG_SEQUENCE && tlv.tag != TAG_SET {
            // DER encodes strings (and every other universal type except
            // SEQUENCE and SET) in primitive form only.
            return Err(TspError::NotDer("constructed universal type"));
        }
        if constructed {
            check_der(tlv.value, depth + 1)?;
        }
        input = rest;
    }
    Ok(())
}

/// Sequential reader over the elements inside a constructed element.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Reader { rest: input }
    }

    fn peek_tag(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    fn next(&mut self, field: &'static str) -> Result<Tlv<'a>, TspError> {
        if self.rest.is_empty() {
            return Err(TspError::Missing(field));
        }
        let (tlv, rest) = read_tlv(self.rest)?;
        self.rest = rest;
        Ok(tlv)
    }

    fn expect(&mut self, tag: u8, field: &'static str) -> Result<Tlv<'a>, TspError> {
        match self.peek_tag() {
            None => Err(TspError::Missing(field)),
            Some(found) if found != tag => Err(TspError::UnexpectedTag {
                field,
                expected: tag,
                found,
            }),
            Some(_) => self.next(field),
        }
    }

    fn optional(&mut self, tag: u8, field: &'static str) -> Result<Option<Tlv<'a>>, TspError> {
        if self.peek_tag() == Some(tag) {
            self.next(field).map(Some)
        } else {
            Ok(None)
        }
    }

    fn finish(&self, after: &'static str) -> Result<(), TspError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(TspError::TrailingData(after))
        }
    }
}

/// Read exactly one element of type `tag` that spans all of `input`.
fn single<'a>(input: &'a [u8], tag: u8, field: &'static str) -> Result<Tlv<'a>, TspError> {
    let mut r = Reader::new(input);
    let tlv = r.expect(tag, field)?;
    r.finish(field)?;
    Ok(tlv)
}

/// The content octets of an INTEGER, checked for minimal encoding.
fn integer_bytes(tlv: Tlv<'_>) -> Result<&[u8], TspError> {
    match tlv.value {
        [] => Err(TspError::NotDer("empty INTEGER")),
        [0x00, next, ..] if next & 0x80 == 0 => Err(TspError::NotDer("non-minimal INTEGER")),
        [0xff, next, ..] if next & 0x80 != 0 => Err(TspError::NotDer("non-minimal INTEGER")),
        bytes => Ok(bytes),
    }
}

/// The unsigned magnitude of a non-negative INTEGER (sign octet removed),
/// or `None` if it is negative.
fn unsigned_magnitude(bytes: &[u8]) -> Option<&[u8]> {
    match bytes {
        [first, ..] if first & 0x80 != 0 => None,
        [0x00, rest @ ..] if !rest.is_empty() => Some(rest),
        _ => Some(bytes),
    }
}

/// A non-negative INTEGER that fits in a `u64`.
fn integer_u64(tlv: Tlv<'_>) -> Result<Option<u64>, TspError> {
    let bytes = integer_bytes(tlv)?;
    Ok(unsigned_magnitude(bytes)
        .filter(|m| m.len() <= 8)
        .map(|m| m.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64)))
}

fn boolean(tlv: Tlv<'_>) -> Result<bool, TspError> {
    match tlv.value {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(TspError::NotDer("BOOLEAN must be one octet, 0x00 or 0xff")),
    }
}

/// Decode an OBJECT IDENTIFIER to dotted-decimal text.
fn oid(tlv: Tlv<'_>) -> Result<String, TspError> {
    let bytes = tlv.value;
    if bytes.is_empty() {
        return Err(TspError::Invalid("empty OBJECT IDENTIFIER"));
    }
    let mut arcs: Vec<u64> = Vec::new();
    let mut value: u64 = 0;
    let mut fresh = true;
    for &b in bytes {
        if fresh && b == 0x80 {
            return Err(TspError::NotDer("OBJECT IDENTIFIER arc with leading 0x80"));
        }
        if value > (u64::MAX >> 7) {
            return Err(TspError::Invalid("OBJECT IDENTIFIER arc too large"));
        }
        value = (value << 7) | (b & 0x7f) as u64;
        fresh = b & 0x80 == 0;
        if fresh {
            arcs.push(value);
            value = 0;
        }
    }
    if !fresh {
        return Err(TspError::Invalid("OBJECT IDENTIFIER ends mid-arc"));
    }
    // The first encoded arc packs the first two: 40 * X + Y, with X <= 2.
    let first = arcs[0];
    let (x, y) = match first {
        0..=39 => (0, first),
        40..=79 => (1, first - 40),
        _ => (2, first - 80),
    };
    let mut text = format!("{x}.{y}");
    for arc in &arcs[1..] {
        text.push('.');
        text.push_str(&arc.to_string());
    }
    Ok(text)
}

/// Decode a named-bit BIT STRING into a mask where bit `n` is `1 << n`.
/// Bits numbered 32 and above are not defined by RFC 3161 and are ignored.
fn named_bits(tlv: Tlv<'_>) -> Result<u32, TspError> {
    let (&unused, bits) = tlv
        .value
        .split_first()
        .ok_or(TspError::NotDer("empty BIT STRING"))?;
    if unused > 7 || (bits.is_empty() && unused != 0) {
        return Err(TspError::NotDer("bad unused-bit count in BIT STRING"));
    }
    if let Some(&last) = bits.last() {
        if last & ((1u8 << unused) - 1) != 0 {
            return Err(TspError::NotDer("nonzero padding bits in BIT STRING"));
        }
    }
    let mut mask = 0u32;
    for (i, &byte) in bits.iter().enumerate().take(4) {
        for k in 0..8 {
            if byte & (0x80 >> k) != 0 {
                mask |= 1 << (i * 8 + k);
            }
        }
    }
    Ok(mask)
}

// ---------------------------------------------------------------------------
// DER writing
// ---------------------------------------------------------------------------

/// Encode one element with a minimal definite length.
fn write_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let octets = len.to_be_bytes();
        let skip = octets.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (octets.len() - skip) as u8);
        out.extend_from_slice(&octets[skip..]);
    }
    out.extend_from_slice(content);
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    write_tlv(&mut out, tag, content);
    out
}

/// Minimal two's-complement content octets of a non-negative integer:
/// leading zero octets dropped, and one zero octet added back when the top
/// bit is set so the value stays positive.
fn uint_content(v: u64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count().min(7);
    let mut out = Vec::with_capacity(9);
    if bytes[skip] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(&bytes[skip..]);
    out
}

/// Build a DER `TimeStampReq` (RFC 3161 section 2.4.1):
///
/// ```text
/// TimeStampReq ::= SEQUENCE {
///    version        INTEGER { v1(1) },
///    messageImprint SEQUENCE { hashAlgorithm sha256 (NULL parameters),
///                              hashedMessage OCTET STRING (digest) },
///    nonce          INTEGER (nonce),
///    certReq        BOOLEAN (TRUE) }
/// ```
///
/// `certReq` asks the TSA to include its certificate in the token, so the
/// token can later be verified without fetching anything. The nonce lets
/// the caller match the response to this request (check
/// [`TstInfo::nonce`]); pick it with [`crate::rand::fill`].
pub fn request(digest: &[u8; 32], nonce: u64) -> Vec<u8> {
    let mut algorithm = tlv(TAG_OID, &SHA256_OID_DER);
    write_tlv(&mut algorithm, TAG_NULL, &[]);
    let mut imprint = tlv(TAG_SEQUENCE, &algorithm);
    write_tlv(&mut imprint, TAG_OCTET_STRING, digest);

    let mut body = tlv(TAG_INTEGER, &[1]);
    write_tlv(&mut body, TAG_SEQUENCE, &imprint);
    write_tlv(&mut body, TAG_INTEGER, &uint_content(nonce));
    write_tlv(&mut body, TAG_BOOLEAN, &[0xff]);
    tlv(TAG_SEQUENCE, &body)
}

// ---------------------------------------------------------------------------
// TimeStampResp
// ---------------------------------------------------------------------------

/// `PKIStatus` (RFC 3161 section 2.4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PkiStatus {
    /// 0: a token is present, as requested.
    Granted,
    /// 1: a token is present, with modifications.
    GrantedWithMods,
    /// 2: the request was refused; see `status_text` and `fail_info`.
    Rejection,
    /// 3: not yet processed.
    Waiting,
    /// 4: a revocation is imminent.
    RevocationWarning,
    /// 5: a revocation has occurred.
    RevocationNotification,
}

impl PkiStatus {
    fn from_code(code: u64) -> Option<PkiStatus> {
        Some(match code {
            0 => PkiStatus::Granted,
            1 => PkiStatus::GrantedWithMods,
            2 => PkiStatus::Rejection,
            3 => PkiStatus::Waiting,
            4 => PkiStatus::RevocationWarning,
            5 => PkiStatus::RevocationNotification,
            _ => return None,
        })
    }

    /// The integer value on the wire.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// True for the two statuses that carry a token.
    pub fn is_granted(self) -> bool {
        matches!(self, PkiStatus::Granted | PkiStatus::GrantedWithMods)
    }
}

/// A parsed `TimeStampResp`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: PkiStatus,
    /// `statusString`: the TSA's human-readable explanation, if any.
    pub status_text: Vec<String>,
    /// `failInfo` as a mask of [`fail_info`] bits, if present.
    pub fail_info: Option<u32>,
    /// The time-stamp token: the complete DER of its CMS `ContentInfo`.
    /// Present exactly when the status is granted. Store these bytes as
    /// they are; [`parse_token`] reads them, and `openssl ts -verify
    /// -token_in` verifies them.
    pub token: Option<Vec<u8>>,
}

/// Parse a DER `TimeStampResp` (RFC 3161 section 2.4.2).
///
/// The whole input must be one well-formed DER element. A granted status
/// requires a token and any other status forbids one, as the RFC says. The
/// token is checked for well-formed DER but not interpreted; use
/// [`parse_token`] for that.
pub fn parse_response(bytes: &[u8]) -> Result<Response, TspError> {
    check_der(bytes, 0)?;
    let resp = single(bytes, TAG_SEQUENCE, "TimeStampResp")?;
    let mut r = Reader::new(resp.value);
    let status_info = r.expect(TAG_SEQUENCE, "PKIStatusInfo")?;
    let token = r.optional(TAG_SEQUENCE, "timeStampToken")?;
    r.finish("TimeStampResp")?;

    let mut s = Reader::new(status_info.value);
    let code = integer_u64(s.expect(TAG_INTEGER, "status")?)?;
    let status = code
        .and_then(PkiStatus::from_code)
        .ok_or(TspError::Invalid("unknown PKIStatus"))?;
    let mut status_text = Vec::new();
    if let Some(free_text) = s.optional(TAG_SEQUENCE, "statusString")? {
        let mut items = Reader::new(free_text.value);
        while items.peek_tag().is_some() {
            let item = items.expect(TAG_UTF8_STRING, "statusString")?;
            let text = std::str::from_utf8(item.value)
                .map_err(|_| TspError::Invalid("statusString is not UTF-8"))?;
            status_text.push(text.to_string());
        }
    }
    let fail_info = match s.optional(TAG_BIT_STRING, "failInfo")? {
        Some(bits) => Some(named_bits(bits)?),
        None => None,
    };
    s.finish("PKIStatusInfo")?;

    match (status.is_granted(), token.is_some()) {
        (true, false) => return Err(TspError::Invalid("granted response without a token")),
        (false, true) => {
            return Err(TspError::Invalid(
                "token in a response that was not granted",
            ))
        }
        _ => {}
    }
    Ok(Response {
        status,
        status_text,
        fail_info,
        token: token.map(|t| t.raw.to_vec()),
    })
}

// ---------------------------------------------------------------------------
// TimeStampToken / TSTInfo
// ---------------------------------------------------------------------------

/// `Accuracy` (RFC 3161 section 2.4.2): the TSA's stated bound on how far
/// `genTime` may be from true UTC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Accuracy {
    pub seconds: Option<u64>,
    pub millis: Option<u16>,
    pub micros: Option<u16>,
}

/// The token's `nonce`, which should equal the one sent in the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Nonce {
    /// A non-negative nonce that fits in 64 bits (always the case for
    /// nonces from [`request`]).
    U64(u64),
    /// Any other value, as the INTEGER's two's-complement content octets.
    Bytes(Vec<u8>),
}

/// The signed content of a time-stamp token (RFC 3161 section 2.4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TstInfo {
    /// Always 1.
    pub version: u64,
    /// The TSA policy under which the token was issued, as a dotted OID.
    pub policy: String,
    /// The imprint's hash algorithm, as a dotted OID ([`OID_SHA256`] for
    /// tokens requested with [`request`]).
    pub hash_algorithm: String,
    /// The hash that was time-stamped.
    pub hashed_message: Vec<u8>,
    /// The token's serial number as unsigned big-endian octets (the DER
    /// sign octet, if any, removed).
    pub serial_number: Vec<u8>,
    /// `genTime` exactly as encoded, e.g. `20261013132322Z` or
    /// `20261013132322.25Z`.
    pub gen_time: String,
    /// `genTime` as seconds since the Unix epoch (UTC).
    pub gen_time_unix: i64,
    /// The fractional part of `genTime`, in nanoseconds (digits beyond the
    /// ninth are dropped).
    pub gen_time_nanos: u32,
    pub accuracy: Option<Accuracy>,
    /// Whether tokens from this TSA can be ordered by `genTime` alone.
    pub ordering: bool,
    pub nonce: Option<Nonce>,
    /// The TSA's name: the DER of the `GeneralName` (without the `[0]`
    /// wrapper), kept raw because rendering X.500 names is out of scope.
    pub tsa: Option<Vec<u8>>,
    /// The `[1]` extensions element, raw, if present.
    pub extensions: Option<Vec<u8>>,
}

impl TstInfo {
    /// The nonce as a `u64`, if present and representable.
    pub fn nonce_u64(&self) -> Option<u64> {
        match self.nonce {
            Some(Nonce::U64(n)) => Some(n),
            _ => None,
        }
    }

    /// True if this token time-stamps exactly `digest` with SHA-256.
    pub fn imprint_matches(&self, digest: &[u8; 32]) -> bool {
        self.hash_algorithm == OID_SHA256 && self.hashed_message == digest
    }
}

/// Parse a time-stamp token (the `ContentInfo` DER from
/// [`Response::token`]) down to its `TSTInfo`.
///
/// Walks `ContentInfo { signedData } -> SignedData ->
/// encapContentInfo { id-ct-TSTInfo } -> eContent OCTET STRING -> TSTInfo`.
/// The rest of `SignedData` (certificates, CRLs, signer infos) must be
/// well-formed DER in the right places but is not interpreted, and the
/// signature is not checked.
pub fn parse_token(token: &[u8]) -> Result<TstInfo, TspError> {
    check_der(token, 0)?;
    let content_info = single(token, TAG_SEQUENCE, "ContentInfo")?;
    let mut ci = Reader::new(content_info.value);
    if oid(ci.expect(TAG_OID, "contentType")?)? != OID_SIGNED_DATA {
        return Err(TspError::Invalid("token content type is not signedData"));
    }
    let explicit = ci.expect(TAG_CTX0, "content")?;
    ci.finish("ContentInfo")?;

    let signed_data = single(explicit.value, TAG_SEQUENCE, "SignedData")?;
    let mut sd = Reader::new(signed_data.value);
    integer_bytes(sd.expect(TAG_INTEGER, "SignedData version")?)?;
    sd.expect(TAG_SET, "digestAlgorithms")?;
    let encap = sd.expect(TAG_SEQUENCE, "encapContentInfo")?;
    sd.optional(TAG_CTX0, "certificates")?;
    sd.optional(TAG_CTX1, "crls")?;
    sd.expect(TAG_SET, "signerInfos")?;
    sd.finish("SignedData")?;

    let mut ec = Reader::new(encap.value);
    if oid(ec.expect(TAG_OID, "eContentType")?)? != OID_TST_INFO {
        return Err(TspError::Invalid("encapsulated content is not TSTInfo"));
    }
    let explicit = ec.expect(TAG_CTX0, "eContent")?;
    ec.finish("encapContentInfo")?;
    let octets = single(explicit.value, TAG_OCTET_STRING, "eContent")?;
    parse_tst_info(octets.value)
}

/// Parse the DER `TSTInfo` carried inside a token's `eContent`.
fn parse_tst_info(der: &[u8]) -> Result<TstInfo, TspError> {
    // The eContent OCTET STRING is primitive, so the token-level check did
    // not look inside it.
    check_der(der, 0)?;
    let tst = single(der, TAG_SEQUENCE, "TSTInfo")?;
    let mut t = Reader::new(tst.value);

    let version = integer_u64(t.expect(TAG_INTEGER, "version")?)?;
    if version != Some(1) {
        return Err(TspError::Invalid("unsupported TSTInfo version"));
    }
    let policy = oid(t.expect(TAG_OID, "policy")?)?;

    let imprint = t.expect(TAG_SEQUENCE, "messageImprint")?;
    let mut mi = Reader::new(imprint.value);
    let algorithm = mi.expect(TAG_SEQUENCE, "hashAlgorithm")?;
    let hashed = mi.expect(TAG_OCTET_STRING, "hashedMessage")?;
    mi.finish("messageImprint")?;
    let mut alg = Reader::new(algorithm.value);
    let hash_algorithm = oid(alg.expect(TAG_OID, "hashAlgorithm")?)?;
    // Hash algorithm parameters are NULL or absent (RFC 5754 section 2);
    // anything else is not a hash algorithm identifier.
    if let Some(params) = alg.optional(TAG_NULL, "hashAlgorithm parameters")? {
        if !params.value.is_empty() {
            return Err(TspError::NotDer("NULL with content"));
        }
    }
    alg.finish("hashAlgorithm")?;

    let serial = integer_bytes(t.expect(TAG_INTEGER, "serialNumber")?)?;
    let serial_number = unsigned_magnitude(serial)
        .ok_or(TspError::Invalid("negative serial number"))?
        .to_vec();

    let time = t.expect(TAG_GENERALIZED_TIME, "genTime")?;
    let (gen_time_unix, gen_time_nanos) = generalized_time(time.value)?;
    let gen_time = String::from_utf8(time.value.to_vec())
        .map_err(|_| TspError::Invalid("genTime is not ASCII"))?;

    let accuracy = match t.optional(TAG_SEQUENCE, "accuracy")? {
        Some(a) => Some(accuracy(a)?),
        None => None,
    };
    let ordering = match t.optional(TAG_BOOLEAN, "ordering")? {
        Some(b) => boolean(b)?,
        None => false,
    };
    let nonce = match t.optional(TAG_INTEGER, "nonce")? {
        Some(n) => Some(match integer_u64(n)? {
            Some(v) => Nonce::U64(v),
            None => Nonce::Bytes(n.value.to_vec()),
        }),
        None => None,
    };
    let tsa = match t.optional(TAG_CTX0, "tsa")? {
        // GeneralName is a CHOICE, so its [0] tag is explicit: exactly one
        // element inside.
        Some(wrapper) => {
            let mut inner = Reader::new(wrapper.value);
            let name = inner.next("tsa")?;
            inner.finish("tsa")?;
            Some(name.raw.to_vec())
        }
        None => None,
    };
    let extensions = t.optional(TAG_CTX1, "extensions")?.map(|e| e.raw.to_vec());
    t.finish("TSTInfo")?;

    Ok(TstInfo {
        version: 1,
        policy,
        hash_algorithm,
        hashed_message: hashed.value.to_vec(),
        serial_number,
        gen_time,
        gen_time_unix,
        gen_time_nanos,
        accuracy,
        ordering,
        nonce,
        tsa,
        extensions,
    })
}

/// `Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL,
/// millis [0] INTEGER (1..999) OPTIONAL, micros [1] INTEGER (1..999) OPTIONAL }`
fn accuracy(tlv: Tlv<'_>) -> Result<Accuracy, TspError> {
    let mut r = Reader::new(tlv.value);
    let small = |t: Tlv<'_>| -> Result<u16, TspError> {
        match integer_u64(t)? {
            Some(v) if v <= 999 => Ok(v as u16),
            _ => Err(TspError::Invalid("accuracy millis or micros out of range")),
        }
    };
    let seconds = match r.optional(TAG_INTEGER, "accuracy seconds")? {
        Some(s) => Some(integer_u64(s)?.ok_or(TspError::Invalid("accuracy seconds out of range"))?),
        None => None,
    };
    let millis = match r.optional(TAG_CTX0_PRIM, "accuracy millis")? {
        Some(m) => Some(small(m)?),
        None => None,
    };
    let micros = match r.optional(TAG_CTX1_PRIM, "accuracy micros")? {
        Some(m) => Some(small(m)?),
        None => None,
    };
    r.finish("accuracy")?;
    Ok(Accuracy {
        seconds,
        millis,
        micros,
    })
}

/// Parse a GeneralizedTime as RFC 3161 requires it (`YYYYMMDDhhmmss`, an
/// optional `.` and fraction digits, then `Z`) into Unix seconds and
/// nanoseconds. Local times and offsets are rejected: RFC 3161 section
/// 2.4.2 mandates UTC with `Z`. A leap second (`60`) is accepted and folds
/// into the following second, as POSIX time cannot represent it.
fn generalized_time(text: &[u8]) -> Result<(i64, u32), TspError> {
    const BAD: TspError = TspError::Invalid("malformed genTime");
    if text.len() < 15 {
        return Err(BAD);
    }
    let (body, rest) = text.split_at(14);
    if !body.iter().all(u8::is_ascii_digit) {
        return Err(BAD);
    }
    let num = |range: std::ops::Range<usize>| {
        body[range]
            .iter()
            .fold(0i64, |acc, &b| acc * 10 + (b - b'0') as i64)
    };
    let (year, month, day) = (num(0..4), num(4..6), num(6..8));
    let (hour, minute, second) = (num(8..10), num(10..12), num(12..14));

    let mut nanos: u32 = 0;
    let rest = match rest {
        [b'.', fraction @ .., b'Z'] => {
            if fraction.is_empty() || !fraction.iter().all(u8::is_ascii_digit) {
                return Err(BAD);
            }
            for (i, &d) in fraction.iter().take(9).enumerate() {
                nanos += (d - b'0') as u32 * 10u32.pow(8 - i as u32);
            }
            &b"Z"[..]
        }
        other => other,
    };
    if rest != b"Z" {
        return Err(TspError::Invalid("genTime is not UTC ('Z')"));
    }

    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(TspError::Invalid("genTime out of range"));
    }
    let days = days_from_civil(year, month, day);
    Ok((days * 86_400 + hour * 3_600 + minute * 60 + second, nanos))
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days from 1970-01-01 to the given proleptic Gregorian date (Howard
/// Hinnant's `days_from_civil`, valid for every year here).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real responses; see tests/fixtures/tsp/README.md for how each was
    // obtained.
    const FREETSA_TSQ: &[u8] = include_bytes!("../tests/fixtures/tsp/freetsa.tsq");
    const FREETSA_TSR: &[u8] = include_bytes!("../tests/fixtures/tsp/freetsa.tsr");
    const DIGICERT_TSQ: &[u8] = include_bytes!("../tests/fixtures/tsp/digicert.tsq");
    const DIGICERT_TSR: &[u8] = include_bytes!("../tests/fixtures/tsp/digicert.tsr");
    const SIGSTORE_TSQ: &[u8] = include_bytes!("../tests/fixtures/tsp/sigstore.tsq");
    const SIGSTORE_TSR: &[u8] = include_bytes!("../tests/fixtures/tsp/sigstore.tsr");
    const MICROSOFT_TSQ: &[u8] = include_bytes!("../tests/fixtures/tsp/microsoft.tsq");
    const MICROSOFT_TSR: &[u8] = include_bytes!("../tests/fixtures/tsp/microsoft.tsr");
    const QUOVADIS_TSQ: &[u8] = include_bytes!("../tests/fixtures/tsp/quovadis.tsq");
    const QUOVADIS_TSR: &[u8] = include_bytes!("../tests/fixtures/tsp/quovadis.tsr");
    const REJECTED_TSR: &[u8] = include_bytes!("../tests/fixtures/tsp/freetsa-rejected.tsr");

    /// Every granted response, for the corruption tests.
    const GRANTED: [&[u8]; 5] = [
        FREETSA_TSR,
        DIGICERT_TSR,
        SIGSTORE_TSR,
        MICROSOFT_TSR,
        QUOVADIS_TSR,
    ];

    const FREETSA_DIGEST: &str = "a06b17bc989c8bd035c8c4e2b0e7fe769d598646c3d0df569c6ba1ba24956d51";
    const FREETSA_NONCE: u64 = 0x3F2E_6A9B_BBF2_33D8;
    const DIGICERT_DIGEST: &str =
        "353dae89fc50a4772177b96eea979aa09711a4d08d1cb470b9f616065a45b62b";
    const DIGICERT_NONCE: u64 = 0xBBBD_8A08_4B59_3BD9;
    const SIGSTORE_DIGEST: &str =
        "a9b693f678dd6c25b56c66c4395a0a7fab85994197e21f9fccb14bc6f8c704dc";
    const SIGSTORE_NONCE: u64 = 0xF56E_935B_88DA_60E2;
    const MICROSOFT_DIGEST: &str =
        "8f198e8dc87bc96766f538dc69b2d9a7a7805e7ec182c75c26f3928dd9e70cc3";
    const MICROSOFT_NONCE: u64 = 0xD3EA_93B9_001C_58D6;
    const QUOVADIS_DIGEST: &str =
        "44aa709ae9ec32e713ed314a0fb039c4767ffffcf0f915c6f316f70f2544066c";
    const QUOVADIS_NONCE: u64 = 0xBFBC_0B08_F3F2_9B53;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn digest(s: &str) -> [u8; 32] {
        unhex(s).try_into().unwrap()
    }

    fn token_of(tsr: &[u8]) -> Vec<u8> {
        parse_response(tsr).unwrap().token.unwrap()
    }

    #[test]
    fn request_matches_openssl_byte_for_byte() {
        // The .tsq files were written by `openssl ts -query -digest <hex>
        // -sha256 -cert`; OpenSSL chose the nonces, read back here.
        assert_eq!(request(&digest(FREETSA_DIGEST), FREETSA_NONCE), FREETSA_TSQ);
        assert_eq!(
            request(&digest(DIGICERT_DIGEST), DIGICERT_NONCE),
            DIGICERT_TSQ
        );
        assert_eq!(
            request(&digest(SIGSTORE_DIGEST), SIGSTORE_NONCE),
            SIGSTORE_TSQ
        );
        assert_eq!(
            request(&digest(MICROSOFT_DIGEST), MICROSOFT_NONCE),
            MICROSOFT_TSQ
        );
        assert_eq!(
            request(&digest(QUOVADIS_DIGEST), QUOVADIS_NONCE),
            QUOVADIS_TSQ
        );
    }

    #[test]
    fn request_nonce_encoding_is_minimal() {
        let d = [7u8; 32];
        let nonce_field = |n: u64| {
            let req = request(&d, n);
            // version (3) + imprint (51) after the 2-byte outer header.
            let at = 2 + 3 + 51;
            let len = req[at + 1] as usize;
            req[at..at + 2 + len].to_vec()
        };
        assert_eq!(nonce_field(0), [0x02, 0x01, 0x00]);
        assert_eq!(nonce_field(0x7f), [0x02, 0x01, 0x7f]);
        assert_eq!(nonce_field(0x80), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(nonce_field(0x0100), [0x02, 0x02, 0x01, 0x00]);
        assert_eq!(
            nonce_field(u64::MAX),
            [0x02, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
        for n in [0, 1, 0x7f, 0x80, 0xff, 0x100, 1 << 63, u64::MAX] {
            let req = request(&d, n);
            check_der(&req, 0).unwrap();
            assert_eq!(req[1] as usize, req.len() - 2);
        }
    }

    #[test]
    fn parses_freetsa_response() {
        let resp = parse_response(FREETSA_TSR).unwrap();
        assert_eq!(resp.status, PkiStatus::Granted);
        assert!(resp.status_text.is_empty());
        assert_eq!(resp.fail_info, None);
        let tst = parse_token(resp.token.as_ref().unwrap()).unwrap();
        assert!(tst.imprint_matches(&digest(FREETSA_DIGEST)));
        assert_eq!(tst.nonce_u64(), Some(FREETSA_NONCE));
        assert_eq!(tst.version, 1);
        assert_eq!(tst.policy, "1.2.3.4.1");
        assert_eq!(tst.serial_number, unhex("09283be9"));
        assert_eq!(tst.gen_time, "20261013132322Z");
        assert_eq!(tst.gen_time_unix, 1_791_897_802);
        assert_eq!(tst.gen_time_nanos, 0);
        assert_eq!(tst.accuracy, None);
        assert!(tst.ordering);
        // directoryName [4], 271 content bytes.
        let tsa = tst.tsa.unwrap();
        assert_eq!(&tsa[..4], &[0xa4, 0x82, 0x01, 0x0f]);
        assert_eq!(tsa.len(), 4 + 271);
        assert_eq!(tst.extensions, None);
    }

    #[test]
    fn parses_digicert_response() {
        let tst = parse_token(&token_of(DIGICERT_TSR)).unwrap();
        assert!(tst.imprint_matches(&digest(DIGICERT_DIGEST)));
        // The high bit is set, so this nonce took nine octets on the wire.
        assert_eq!(tst.nonce, Some(Nonce::U64(DIGICERT_NONCE)));
        assert_eq!(tst.policy, "2.16.840.1.114412.7.1");
        assert_eq!(tst.serial_number, unhex("c1bbd5d7334c40d6aba31f591d4ef1d5"));
        assert_eq!(tst.gen_time, "20261013132330Z");
        assert_eq!(tst.gen_time_unix, 1_791_897_810);
        assert!(!tst.ordering);
        assert_eq!(tst.tsa, None);
        assert_eq!(tst.accuracy, None);
    }

    #[test]
    fn parses_sigstore_response() {
        let tst = parse_token(&token_of(SIGSTORE_TSR)).unwrap();
        assert!(tst.imprint_matches(&digest(SIGSTORE_DIGEST)));
        assert!(!tst.imprint_matches(&digest(FREETSA_DIGEST)));
        assert_eq!(tst.nonce_u64(), Some(SIGSTORE_NONCE));
        assert_eq!(tst.policy, "1.3.6.1.4.1.57264.2");
        assert_eq!(
            tst.serial_number,
            unhex("54e6763c8a1ac4be9df73295b0c79b1c4dfa6625")
        );
        assert_eq!(tst.gen_time_unix, 1_791_897_826);
        assert_eq!(
            tst.accuracy,
            Some(Accuracy {
                seconds: Some(1),
                millis: None,
                micros: None
            })
        );
        assert_eq!(tst.tsa.as_deref().map(|t| t[0]), Some(0xa4));
    }

    #[test]
    fn parses_microsoft_response_with_fractional_time() {
        let resp = parse_response(MICROSOFT_TSR).unwrap();
        assert_eq!(resp.status, PkiStatus::Granted);
        let tst = parse_token(resp.token.as_ref().unwrap()).unwrap();
        assert!(tst.imprint_matches(&digest(MICROSOFT_DIGEST)));
        assert_eq!(tst.nonce_u64(), Some(MICROSOFT_NONCE));
        assert_eq!(tst.policy, "1.3.6.1.4.1.601.10.3.1");
        assert_eq!(tst.serial_number, unhex("6ac8e5f62932"));
        assert_eq!(tst.gen_time, "20261013145908.811Z");
        assert_eq!(tst.gen_time_unix, 1_791_903_548);
        assert_eq!(tst.gen_time_nanos, 811_000_000);
        assert_eq!(
            tst.accuracy,
            Some(Accuracy {
                seconds: None,
                millis: Some(500),
                micros: None
            })
        );
        assert_eq!(tst.tsa.as_deref().map(|t| t[0]), Some(0xa4));
    }

    #[test]
    fn parses_quovadis_response_with_status_text_and_extensions() {
        let resp = parse_response(QUOVADIS_TSR).unwrap();
        assert_eq!(resp.status, PkiStatus::Granted);
        assert_eq!(resp.status_text, ["Operation Okay"]);
        let tst = parse_token(resp.token.as_ref().unwrap()).unwrap();
        assert!(tst.imprint_matches(&digest(QUOVADIS_DIGEST)));
        assert_eq!(tst.nonce_u64(), Some(QUOVADIS_NONCE));
        assert_eq!(tst.policy, "1.3.6.1.4.1.8024.0.2000.6");
        assert_eq!(tst.serial_number, unhex("6123b9e9f97f61c5"));
        assert_eq!(tst.gen_time, "20261013145909Z");
        assert_eq!(tst.gen_time_unix, 1_791_903_549);
        assert_eq!(tst.accuracy.and_then(|a| a.millis), Some(997));
        // A qcStatements extension: [1] wrapper, 29 octets in all.
        let ext = tst.extensions.unwrap();
        assert_eq!((ext[0], ext.len()), (0xa1, 29));
    }

    #[test]
    fn parses_rejection() {
        let resp = parse_response(REJECTED_TSR).unwrap();
        assert_eq!(resp.status, PkiStatus::Rejection);
        assert_eq!(resp.status.code(), 2);
        assert!(!resp.status.is_granted());
        assert_eq!(
            resp.status_text,
            ["Message digest algorithm is not supported."]
        );
        assert_eq!(resp.fail_info, Some(fail_info::BAD_ALG));
        assert_eq!(resp.token, None);
    }

    #[test]
    fn token_round_trips_through_response() {
        // The token is a sub-slice of the response, byte for byte.
        let token = token_of(FREETSA_TSR);
        let at = FREETSA_TSR
            .windows(token.len())
            .position(|w| w == token.as_slice());
        assert!(at.is_some());
    }

    #[test]
    fn every_truncation_is_an_error() {
        for tsr in GRANTED.into_iter().chain([REJECTED_TSR]) {
            for len in 0..tsr.len() {
                assert!(parse_response(&tsr[..len]).is_err(), "len {len}");
            }
        }
        for tsr in GRANTED {
            let token = token_of(tsr);
            for len in 0..token.len() {
                assert!(parse_token(&token[..len]).is_err(), "len {len}");
            }
        }
    }

    #[test]
    fn trailing_bytes_are_an_error() {
        for tsr in [FREETSA_TSR, SIGSTORE_TSR, REJECTED_TSR] {
            let mut padded = tsr.to_vec();
            padded.push(0);
            assert!(parse_response(&padded).is_err());
        }
        let mut token = token_of(DIGICERT_TSR);
        token.extend_from_slice(&[0x05, 0x00]);
        assert!(parse_token(&token).is_err());
    }

    #[test]
    fn single_byte_corruption_never_panics() {
        // Every byte of every fixture is corrupted once. The masks rotate so
        // tags, lengths and contents each see low-bit, high-bit and full
        // flips without running every mask at every offset; the small
        // fixtures get all three masks everywhere.
        const MASKS: [u8; 3] = [0x01, 0x80, 0xff];
        let attempt = |buf: &[u8]| {
            if let Ok(resp) = parse_response(buf) {
                if let Some(token) = resp.token {
                    let _ = parse_token(&token);
                }
            }
        };
        for tsr in GRANTED.into_iter().chain([REJECTED_TSR]) {
            let mut buf = tsr.to_vec();
            let every_mask = buf.len() < 2000;
            for i in 0..buf.len() {
                for (m, mask) in MASKS.into_iter().enumerate() {
                    if every_mask || i % MASKS.len() == m {
                        buf[i] ^= mask;
                        attempt(&buf);
                        buf[i] ^= mask;
                    }
                }
            }
        }
    }

    #[test]
    fn corrupting_the_tstinfo_changes_or_breaks_the_result() {
        // A flip inside the signed TSTInfo either fails to parse or yields
        // different contents; it can never yield the original contents.
        let token = token_of(SIGSTORE_TSR);
        let original = parse_token(&token).unwrap();
        // The sigstore TSTInfo is `30 81 ac` (172 content octets) followed
        // by `version 1`; see the fixture README for the full dump.
        let header = [0x30, 0x81, 0xac, 0x02, 0x01, 0x01];
        let start = token.windows(6).position(|w| w == header).unwrap();
        let mut buf = token.clone();
        for i in start..start + 3 + 0xac {
            buf[i] ^= 0x01;
            if let Ok(tst) = parse_token(&buf) {
                assert_ne!(tst, original, "flip at {i} went unnoticed");
            }
            buf[i] ^= 0x01;
        }
    }

    #[test]
    fn random_mutations_never_panic() {
        // Deterministic xorshift so failures reproduce.
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..3000 {
            let mut buf = SIGSTORE_TSR.to_vec();
            for _ in 0..(next() % 8 + 1) {
                let i = (next() as usize) % buf.len();
                buf[i] = next() as u8;
            }
            let _ = parse_response(&buf);
            let cut = (next() as usize) % buf.len();
            let _ = parse_token(&buf[cut..]);
        }
        for len in 0..64 {
            let junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = parse_response(&junk);
            let _ = parse_token(&junk);
        }
    }

    #[test]
    fn rejects_non_der_lengths() {
        // Indefinite length.
        assert_eq!(
            read_tlv(&[0x30, 0x80, 0x00, 0x00]).unwrap_err(),
            TspError::NotDer("indefinite length")
        );
        // Long form for a short length, and a leading zero length octet.
        assert!(matches!(
            read_tlv(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]),
            Err(TspError::NotDer(_))
        ));
        let mut padded = vec![0x04, 0x82, 0x00, 0x80];
        padded.extend_from_slice(&[0; 0x80]);
        assert!(matches!(read_tlv(&padded), Err(TspError::NotDer(_))));
        // The minimal long form is fine.
        let mut ok = vec![0x04, 0x81, 0x80];
        ok.extend_from_slice(&[0; 0x80]);
        assert_eq!(read_tlv(&ok).unwrap().0.value.len(), 0x80);
        // Lengths past the input, including ones that would overflow.
        assert_eq!(
            read_tlv(&[0x04, 0x05, 1, 2]).unwrap_err(),
            TspError::Truncated
        );
        assert_eq!(
            read_tlv(&[0x04, 0x84, 0xff, 0xff, 0xff, 0xff, 0]).unwrap_err(),
            TspError::Truncated
        );
        assert!(matches!(
            read_tlv(&[0x04, 0x89, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
            Err(TspError::NotDer(_))
        ));
        assert!(matches!(read_tlv(&[0x04, 0xff]), Err(TspError::NotDer(_))));
        // Truncated headers.
        assert_eq!(read_tlv(&[]).unwrap_err(), TspError::Truncated);
        assert_eq!(read_tlv(&[0x30]).unwrap_err(), TspError::Truncated);
        assert_eq!(
            read_tlv(&[0x30, 0x82, 0x01]).unwrap_err(),
            TspError::Truncated
        );
        // Multi-byte tags.
        assert!(matches!(
            read_tlv(&[0x1f, 0x81, 0x00, 0x00]),
            Err(TspError::NotDer(_))
        ));
    }

    #[test]
    fn rejects_other_ber_only_forms() {
        // Constructed OCTET STRING.
        assert!(matches!(
            check_der(&[0x24, 0x03, 0x04, 0x01, 0x00], 0),
            Err(TspError::NotDer(_))
        ));
        // End-of-contents marker.
        assert!(matches!(
            check_der(&[0x00, 0x00], 0),
            Err(TspError::NotDer(_))
        ));
        // Non-minimal INTEGERs.
        let int = |v: &'static [u8]| Tlv {
            tag: TAG_INTEGER,
            value: v,
            raw: v,
        };
        assert!(integer_bytes(int(&[0x00, 0x7f])).is_err());
        assert!(integer_bytes(int(&[0xff, 0x80])).is_err());
        assert!(integer_bytes(int(&[])).is_err());
        assert!(integer_bytes(int(&[0x00, 0x80])).is_ok());
        assert!(integer_bytes(int(&[0x00])).is_ok());
        assert_eq!(
            integer_u64(int(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])),
            Ok(Some(u64::MAX))
        );
        assert_eq!(integer_u64(int(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0])), Ok(None));
        assert_eq!(integer_u64(int(&[0x80])), Ok(None));
        // BOOLEAN other than 0x00 / 0xff.
        let b = |v: &'static [u8]| Tlv {
            tag: TAG_BOOLEAN,
            value: v,
            raw: v,
        };
        assert!(boolean(b(&[0x01])).is_err());
        assert!(boolean(b(&[0xff, 0xff])).is_err());
    }

    #[test]
    fn depth_limit() {
        // 100 nested SEQUENCEs: well-formed, but deeper than MAX_DEPTH.
        let mut der = vec![0x05, 0x00];
        for _ in 0..100 {
            let mut outer = Vec::new();
            write_tlv(&mut outer, TAG_SEQUENCE, &der);
            der = outer;
        }
        assert_eq!(check_der(&der, 0), Err(TspError::TooDeep));
        assert_eq!(parse_response(&der), Err(TspError::TooDeep));
        assert_eq!(parse_token(&der), Err(TspError::TooDeep));
    }

    #[test]
    fn decodes_oids() {
        let o = |v: &'static [u8]| {
            oid(Tlv {
                tag: TAG_OID,
                value: v,
                raw: v,
            })
        };
        assert_eq!(o(&SHA256_OID_DER).unwrap(), OID_SHA256);
        assert_eq!(
            o(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04]).unwrap(),
            OID_TST_INFO
        );
        assert_eq!(o(&[0x00]).unwrap(), "0.0");
        assert_eq!(o(&[0x27]).unwrap(), "0.39");
        assert_eq!(o(&[0x28]).unwrap(), "1.0");
        assert_eq!(o(&[0x88, 0x37, 0x03]).unwrap(), "2.999.3");
        assert!(o(&[]).is_err());
        assert!(o(&[0x2a, 0x86]).is_err()); // ends mid-arc
        assert!(o(&[0x2a, 0x80, 0x01]).is_err()); // non-minimal arc
        assert!(
            o(&[0x2a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]).is_err()
        );
    }

    #[test]
    fn decodes_failure_bits() {
        let bits = |v: &'static [u8]| {
            named_bits(Tlv {
                tag: TAG_BIT_STRING,
                value: v,
                raw: v,
            })
        };
        assert_eq!(bits(&[0x07, 0x80]), Ok(fail_info::BAD_ALG));
        assert_eq!(bits(&[0x02, 0x04]), Ok(fail_info::BAD_DATA_FORMAT));
        assert_eq!(
            bits(&[0x06, 0x00, 0x00, 0x00, 0x40]),
            Ok(fail_info::SYSTEM_FAILURE)
        );
        assert_eq!(
            bits(&[0x06, 0x00, 0x00, 0x40]),
            Ok(fail_info::ADD_INFO_NOT_AVAILABLE)
        );
        assert_eq!(
            bits(&[0x00, 0xa0, 0x03]),
            Ok(fail_info::BAD_ALG
                | fail_info::BAD_REQUEST
                | fail_info::TIME_NOT_AVAILABLE
                | fail_info::UNACCEPTED_POLICY)
        );
        assert_eq!(bits(&[0x00]), Ok(0));
        assert!(bits(&[]).is_err());
        assert!(bits(&[0x08, 0x00]).is_err());
        assert!(bits(&[0x01]).is_err());
        assert!(bits(&[0x07, 0x81]).is_err()); // nonzero padding bit
    }

    #[test]
    fn parses_generalized_time() {
        let t = |s: &str| generalized_time(s.as_bytes());
        assert_eq!(t("19700101000000Z"), Ok((0, 0)));
        assert_eq!(t("20261013132322Z"), Ok((1_791_897_802, 0)));
        assert_eq!(t("20000229235959Z"), Ok((951_868_799, 0)));
        assert_eq!(t("99991231235959Z"), Ok((253_402_300_799, 0)));
        assert_eq!(t("19691231235959Z"), Ok((-1, 0)));
        assert_eq!(t("20261013132322.5Z"), Ok((1_791_897_802, 500_000_000)));
        assert_eq!(t("20261013132322.123Z"), Ok((1_791_897_802, 123_000_000)));
        assert_eq!(
            t("20261013132322.123456789123Z"),
            Ok((1_791_897_802, 123_456_789))
        );
        // Leap second folds forward.
        assert_eq!(t("20161231235960Z"), t("20170101000000Z"));
        for bad in [
            "",
            "20261013132322",
            "20261013132322+0000",
            "202610131323Z",
            "20261013132322.Z",
            "20261013132322.5",
            "20261013132322,5Z",
            "20261013132322ZZ",
            "2026101313232aZ",
            "20261313132322Z",
            "20260230132322Z",
            "20250229000000Z",
            "21000229000000Z",
            "20261000132322Z",
            "20261013242322Z",
            "20261013136022Z",
            "20261013132361Z",
            "-0261013132322Z",
        ] {
            assert!(t(bad).is_err(), "{bad:?}");
        }
        assert!(t("20240229000000Z").is_ok());
        assert!(t("20000229000000Z").is_ok());
    }

    #[test]
    fn granted_status_requires_token() {
        // TimeStampResp { PKIStatusInfo { status 0 } } with no token.
        let granted_no_token = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00];
        assert_eq!(
            parse_response(&granted_no_token),
            Err(TspError::Invalid("granted response without a token"))
        );
        let waiting = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x03];
        assert_eq!(parse_response(&waiting).unwrap().status, PkiStatus::Waiting);
        let unknown = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x06];
        assert!(parse_response(&unknown).is_err());
        // A rejection that nevertheless carries a token is refused.
        let token = token_of(SIGSTORE_TSR);
        let mut body = tlv(TAG_SEQUENCE, &tlv(TAG_INTEGER, &[2]));
        body.extend_from_slice(&token);
        let rejected_with_token = tlv(TAG_SEQUENCE, &body);
        assert!(parse_response(&rejected_with_token).is_err());
        let mut body = tlv(TAG_SEQUENCE, &tlv(TAG_INTEGER, &[0]));
        body.extend_from_slice(&token);
        assert!(parse_response(&tlv(TAG_SEQUENCE, &body)).is_ok());
    }

    #[test]
    fn token_requires_signed_tstinfo() {
        // A request is well-formed DER but not a token.
        assert!(parse_token(FREETSA_TSQ).is_err());
        // Neither is a whole response.
        assert!(parse_token(FREETSA_TSR).is_err());
        assert!(parse_response(FREETSA_TSQ).is_err());
    }
}
