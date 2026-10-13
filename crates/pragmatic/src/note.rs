//! C2SP signed notes, transparency-log checkpoints and `cosignature/v1`
//! witness cosignatures: parsing, encoding and Ed25519 verification.
//!
//! Pragmatic Server anchors journals in one append-only Merkle log, and each
//! anchoring batch ends in a *checkpoint*: the log's origin, tree size and
//! root hash, signed by the server's Ed25519 key. Witnesses cosign
//! checkpoints after checking consistency with the last one they saw, and
//! evidence bundles carry both. Rather than inventing a format, Pragmatic
//! uses the C2SP formats that Go's checksum database, Sigstore and the
//! public witness network already speak, so existing tooling can read,
//! verify and witness a Pragmatic log:
//!
//! - [`Note`]: a [signed note] (`c2sp.org/signed-note`), a text followed by
//!   a blank line and one or more lines of the form
//!   `<em dash U+2014> <key name> <base64(key ID ‖ signature)>`.
//! - [`Checkpoint`]: the note text of a [checkpoint]
//!   (`c2sp.org/tlog-checkpoint`), `origin`, decimal tree size and base64
//!   root hash, each on its own line, then optional extension lines.
//! - [`VerifierKey`]: a *vkey*, `<name>+<hex key ID>+<base64(type ‖ public
//!   key)>`, for signature type `0x01` (Ed25519 over the note text, used by
//!   logs) or `0x04` (timestamped Ed25519 checkpoint cosignatures from
//!   [tlog-cosignature], used by witnesses).
//! - [`verify_note`]: which configured keys signed a note, applying the
//!   signed-note rules for known and unknown keys.
//!
//! Only the two Ed25519 signature types are supported. ML-DSA-44
//! cosignatures (type `0x06`), which tlog-checkpoint now recommends for new
//! witnesses, need a post-quantum verifier the core does not have; lines
//! from such keys are treated like any other unknown key and ignored, and
//! a vkey of that type is rejected rather than silently trusted.
//!
//! Signing is not here. Only the server signs, with an audited Ed25519
//! crate; the core needs to *check* signatures (in the CLI, the Python
//! module and the server's witness endpoint), which [`crate::ed25519`]
//! does without dependencies. [`cosignature_v1_message`] is public so the
//! server signs exactly the bytes this module verifies.
//!
//! # Strictness
//!
//! Notes, checkpoints and keys arrive from logs and witnesses that may be
//! hostile, and must mean the same thing to every verifier, so the parsers
//! accept only canonical text:
//!
//! - base64 is standard-alphabet, padded and canonical (nonzero padding
//!   bits are rejected), as both specifications require of decoders;
//! - the key ID in a vkey is eight lowercase hex digits, as signed-note's
//!   conventions define hex (Go's `sumdb/note` also accepts uppercase);
//! - a tree size is an ASCII decimal without leading zeros that fits a
//!   `u64`, and the root decodes to exactly 32 bytes;
//! - notes are UTF-8 without control characters other than newline; key
//!   names are non-empty and contain no Unicode white space and no `+`;
//! - a `cosignature/v1` key's name is a cosigner name, which
//!   tlog-cosignature also limits to [`MAX_ORIGIN_LEN`] bytes;
//! - at most [`MAX_SIGNATURES`] signature lines, the limit Go uses (the
//!   specification requires accepting at least 16).
//!
//! One rule is enforced only when writing. tlog-checkpoint takes its
//! origins from tlog-cosignature, which allows at most [`MAX_ORIGIN_LEN`]
//! bytes and no Unicode white space, `+` or control characters.
//! [`Checkpoint::encode`] enforces that, so the server never signs a
//! checkpoint that a strict witness would refuse. [`Checkpoint::parse`]
//! only requires a non-empty line: the Go checksum database's origin
//! `go.sum database tree` predates the rule, and an origin is never trusted
//! from the note anyway, since callers compare it with the origin they
//! configured.
//!
//! # Verification rules
//!
//! [`verify_note`] follows signed-note: a signature line is from a known key
//! only if both its key name and key ID match a configured [`VerifierKey`];
//! lines from unknown keys are ignored. Every line from a known key must
//! verify, otherwise the whole note is rejected (the specification says
//! SHOULD; Go's `sumdb/note` checks only the first line per key, this
//! module checks them all). If no known key signed, the note is rejected.
//!
//! Each known key may sign at most one distinct line. Byte-identical
//! repeats are harmless and the key is reported once, as in Go, so a
//! repeated line cannot make one witness count twice. Two *different*
//! lines from one known key reject the note: tlog-checkpoint forbids two
//! lines with the same key name and key ID, and for a cosigner they would
//! let whoever assembled the note choose which signed time is reported.
//!
//! Configured keys that are equal in every field are one key, so merging
//! key lists from several sources (the witness keys built into the CLI and
//! those given on the command line, say) cannot make a valid note fail.
//! Go's `VerifierList` calls such a list ambiguous. Distinct keys that
//! share a name and key ID are ambiguous here too, and a line that matches
//! them rejects the note.
//!
//! [signed note]: https://github.com/C2SP/C2SP/blob/main/signed-note.md
//! [checkpoint]: https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md
//! [tlog-cosignature]: https://github.com/C2SP/C2SP/blob/main/tlog-cosignature.md

use std::fmt;

use crate::ed25519;
use crate::encoding::{
    base64_decode, base64_decode_exact, base64_encode, hex_decode_exact, hex_encode,
};
use crate::sha256::Sha256;

/// The most signature lines a note may carry. Go's `sumdb/note` rejects
/// notes with more than 100, and signed-note requires verifiers to accept
/// at least 16.
pub const MAX_SIGNATURES: usize = 100;

/// The longest log origin or cosigner name tlog-cosignature allows, in
/// bytes. Its ML-DSA signed message encodes both with a one-byte length.
pub const MAX_ORIGIN_LEN: usize = 255;

/// Each signature line starts with an em dash (U+2014) and a space.
const SIGNATURE_PREFIX: &str = "\u{2014} ";

/// A signed-note signature type: the byte that is hashed into the key ID
/// and prefixes the public key in a vkey.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureType {
    /// `0x01`: Ed25519 over the note text (signed-note). Logs sign their
    /// checkpoints with this type.
    Ed25519,
    /// `0x04`: an Ed25519 checkpoint cosignature (tlog-cosignature): an
    /// 8-byte big-endian Unix timestamp followed by an Ed25519 signature
    /// over `"cosignature/v1\ntime <timestamp>\n"` and the note text.
    /// Witnesses sign with this type.
    CosignatureV1,
}

impl SignatureType {
    /// The type's identifier byte.
    pub fn id(self) -> u8 {
        match self {
            SignatureType::Ed25519 => 0x01,
            SignatureType::CosignatureV1 => 0x04,
        }
    }

    /// The type for an identifier byte, if it is one this module verifies.
    pub fn from_id(id: u8) -> Option<SignatureType> {
        match id {
            0x01 => Some(SignatureType::Ed25519),
            0x04 => Some(SignatureType::CosignatureV1),
            _ => None,
        }
    }

    /// Length of the signature bytes after the key ID.
    fn signature_len(self) -> usize {
        match self {
            SignatureType::Ed25519 => ed25519::SIGNATURE_LEN,
            SignatureType::CosignatureV1 => 8 + ed25519::SIGNATURE_LEN,
        }
    }
}

/// Why a note, checkpoint or key was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NoteError {
    /// The text is not a well-formed signed note, or a signature line is
    /// malformed.
    Malformed(&'static str),
    /// The note text is not a well-formed checkpoint, or a checkpoint
    /// cannot be encoded.
    Checkpoint(&'static str),
    /// A verifier key is malformed or inconsistent.
    VerifierKey(&'static str),
    /// A signature line matches more than one distinct configured key.
    AmbiguousKey { name: String, key_id: [u8; 4] },
    /// A signature from a configured key does not verify.
    InvalidSignature { name: String, key_id: [u8; 4] },
    /// A configured key signed two different lines of one note, which
    /// tlog-checkpoint forbids.
    RepeatedKey { name: String, key_id: [u8; 4] },
    /// No configured key signed the note.
    NoVerifiedSignature,
}

impl fmt::Display for NoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NoteError::Malformed(why) => write!(f, "malformed note: {why}"),
            NoteError::Checkpoint(why) => write!(f, "malformed checkpoint: {why}"),
            NoteError::VerifierKey(why) => write!(f, "malformed verifier key: {why}"),
            NoteError::AmbiguousKey { name, key_id } => {
                write!(f, "ambiguous key {name}+{}", hex_encode(key_id))
            }
            NoteError::InvalidSignature { name, key_id } => {
                write!(f, "invalid signature for key {name}+{}", hex_encode(key_id))
            }
            NoteError::RepeatedKey { name, key_id } => {
                write!(
                    f,
                    "two different signatures for key {name}+{}",
                    hex_encode(key_id)
                )
            }
            NoteError::NoVerifiedSignature => f.write_str("note has no verifiable signatures"),
        }
    }
}

impl std::error::Error for NoteError {}

/// True for the characters signed notes forbid: ASCII controls other than
/// newline.
fn is_forbidden_control(c: char) -> bool {
    c < ' ' && c != '\n'
}

/// A valid key name: non-empty, no Unicode white space (Rust's
/// `char::is_whitespace` and Go's `unicode.IsSpace` agree on the set), no
/// `+`, and no control characters.
pub fn is_valid_key_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|c| c.is_whitespace() || c == '+' || c < ' ')
}

/// A valid log origin or cosigner name, which tlog-cosignature defines the
/// same way (one string may be both): a valid key name of at most
/// [`MAX_ORIGIN_LEN`] bytes. Signed-note key names have no length limit,
/// so this is stricter than [`is_valid_key_name`].
pub fn is_valid_origin(origin: &str) -> bool {
    origin.len() <= MAX_ORIGIN_LEN && is_valid_key_name(origin)
}

/// The recommended key ID: the first four bytes of
/// `SHA-256(name ‖ 0x0A ‖ type ‖ public key)`.
pub fn key_id(name: &str, signature_type: SignatureType, public_key: &[u8; 32]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(&[0x0a, signature_type.id()]);
    h.update(public_key);
    let digest = h.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

/// The message an Ed25519 `cosignature/v1` signs: `"cosignature/v1"`,
/// `"time <timestamp>"` (ASCII decimal), each ending in a newline, then the
/// checkpoint body. Witnesses sign this; [`VerifierKey::verify`] checks it.
pub fn cosignature_v1_message(timestamp: u64, body: &str) -> String {
    format!("cosignature/v1\ntime {timestamp}\n{body}")
}

// ---------------------------------------------------------------------------
// Signature lines and notes
// ---------------------------------------------------------------------------

/// One signature line of a note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteSignature {
    /// The key name.
    pub name: String,
    /// The 4-byte key ID (a big-endian `uint32` in the specification).
    pub key_id: [u8; 4],
    /// The signature bytes after the key ID. For `cosignature/v1` this is
    /// the 8-byte timestamp followed by the Ed25519 signature.
    pub signature: Vec<u8>,
}

impl NoteSignature {
    /// Parse one signature line, without its trailing newline:
    /// `<em dash> <name> <base64(key ID ‖ signature)>`.
    pub fn parse_line(line: &str) -> Result<NoteSignature, NoteError> {
        if line.chars().any(|c| c < ' ') {
            return Err(NoteError::Malformed("control character in signature line"));
        }
        let rest = line
            .strip_prefix(SIGNATURE_PREFIX)
            .ok_or(NoteError::Malformed(
                "signature line does not start with an em dash and a space",
            ))?;
        let (name, b64) = rest
            .split_once(' ')
            .ok_or(NoteError::Malformed("signature line has no signature"))?;
        if !is_valid_key_name(name) {
            return Err(NoteError::Malformed("invalid key name"));
        }
        let raw = base64_decode(b64)
            .map_err(|_| NoteError::Malformed("signature is not canonical base64"))?;
        if raw.len() < 5 {
            return Err(NoteError::Malformed("signature too short"));
        }
        Ok(NoteSignature {
            name: name.to_string(),
            key_id: [raw[0], raw[1], raw[2], raw[3]],
            signature: raw[4..].to_vec(),
        })
    }

    /// The signature line, without a trailing newline. Fails if the name is
    /// invalid or the signature is empty, which [`parse_line`] would reject.
    ///
    /// [`parse_line`]: NoteSignature::parse_line
    pub fn to_line(&self) -> Result<String, NoteError> {
        if !is_valid_key_name(&self.name) {
            return Err(NoteError::Malformed("invalid key name"));
        }
        if self.signature.is_empty() {
            return Err(NoteError::Malformed("signature too short"));
        }
        let mut raw = Vec::with_capacity(4 + self.signature.len());
        raw.extend_from_slice(&self.key_id);
        raw.extend_from_slice(&self.signature);
        Ok(format!(
            "{SIGNATURE_PREFIX}{} {}",
            self.name,
            base64_encode(&raw)
        ))
    }

    /// The key ID as the specification's big-endian `uint32`.
    pub fn key_id_u32(&self) -> u32 {
        u32::from_be_bytes(self.key_id)
    }

    /// The timestamp of a `cosignature/v1` signature: the first eight bytes,
    /// big-endian, if the signature has the cosignature length. This reads
    /// an unverified field; only trust it after [`VerifierKey::verify`].
    pub fn cosignature_timestamp(&self) -> Option<u64> {
        if self.signature.len() != SignatureType::CosignatureV1.signature_len() {
            return None;
        }
        let ts: [u8; 8] = self.signature[..8].try_into().expect("8 bytes");
        Some(u64::from_be_bytes(ts))
    }
}

/// A signed note: the text (`body`) and its signature lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    /// The note text, including its final newline but not the blank line
    /// that separates it from the signatures. It may contain blank lines.
    pub body: String,
    /// The signature lines in order.
    pub signatures: Vec<NoteSignature>,
}

impl Note {
    /// Parse a signed note. The text is split at its *last* blank line; at
    /// least one and at most [`MAX_SIGNATURES`] signature lines must
    /// follow, each ending in a newline. No signature is verified here.
    pub fn parse(text: &str) -> Result<Note, NoteError> {
        if text.chars().any(is_forbidden_control) {
            return Err(NoteError::Malformed("control character"));
        }
        let split = text
            .rfind("\n\n")
            .ok_or(NoteError::Malformed("no blank line before the signatures"))?;
        let body = &text[..split + 1];
        let block = &text[split + 2..];
        let lines = block
            .strip_suffix('\n')
            .ok_or(NoteError::Malformed("signatures do not end in a newline"))?;
        let mut signatures = Vec::new();
        for line in lines.split('\n') {
            if signatures.len() == MAX_SIGNATURES {
                return Err(NoteError::Malformed("too many signatures"));
            }
            signatures.push(NoteSignature::parse_line(line)?);
        }
        Ok(Note {
            body: body.to_string(),
            signatures,
        })
    }

    /// [`Note::parse`] for bytes that must be UTF-8 (such as a request
    /// body).
    pub fn parse_bytes(bytes: &[u8]) -> Result<Note, NoteError> {
        let text = std::str::from_utf8(bytes).map_err(|_| NoteError::Malformed("not UTF-8"))?;
        Note::parse(text)
    }

    /// The note as text: body, blank line, signature lines. Fails for
    /// anything [`Note::parse`] would not read back identically: a body
    /// that is empty, lacks its final newline or contains control
    /// characters, no signatures or more than [`MAX_SIGNATURES`], or an
    /// invalid signature line.
    pub fn encode(&self) -> Result<String, NoteError> {
        if !self.body.ends_with('\n') {
            return Err(NoteError::Malformed("text does not end in a newline"));
        }
        if self.body.chars().any(is_forbidden_control) {
            return Err(NoteError::Malformed("control character"));
        }
        if self.signatures.is_empty() {
            return Err(NoteError::Malformed("no signatures"));
        }
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(NoteError::Malformed("too many signatures"));
        }
        let mut out = String::with_capacity(self.body.len() + 1 + 100 * self.signatures.len());
        out.push_str(&self.body);
        out.push('\n');
        for sig in &self.signatures {
            out.push_str(&sig.to_line()?);
            out.push('\n');
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Verifier keys and verification
// ---------------------------------------------------------------------------

/// A public key that verifies note signatures, with the name and key ID
/// that signature lines must carry to be attributed to it.
///
/// The fields are private so every value is consistent: the key ID is the
/// one derived from the name, type and key, the name is valid, and the
/// public key is a canonical Ed25519 point that is not of small order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VerifierKey {
    name: String,
    key_id: [u8; 4],
    signature_type: SignatureType,
    public_key: [u8; 32],
}

impl VerifierKey {
    /// A key for `name` with the derived key ID.
    ///
    /// A `cosignature/v1` key's name is a cosigner name, so it must also
    /// satisfy [`is_valid_origin`]. An Ed25519 note key's name only has to
    /// be a valid key name: signed-note sets no length limit, and Go's
    /// `sumdb/note` accepts longer names.
    pub fn new(
        name: &str,
        signature_type: SignatureType,
        public_key: [u8; 32],
    ) -> Result<VerifierKey, NoteError> {
        if !is_valid_key_name(name) {
            return Err(NoteError::VerifierKey("invalid key name"));
        }
        if signature_type == SignatureType::CosignatureV1 && !is_valid_origin(name) {
            return Err(NoteError::VerifierKey(
                "cosigner name is longer than 255 bytes",
            ));
        }
        if !ed25519::is_valid_public_key(&public_key) {
            return Err(NoteError::VerifierKey(
                "public key is not a valid Ed25519 point of large order",
            ));
        }
        Ok(VerifierKey {
            name: name.to_string(),
            key_id: key_id(name, signature_type, &public_key),
            signature_type,
            public_key,
        })
    }

    /// Parse a vkey: `<name>+<hex key ID>+<base64(type ‖ public key)>`. The
    /// base64 part may itself contain `+`, so only the first two `+`
    /// separate fields. The key ID must match the one derived from the
    /// rest.
    pub fn parse(vkey: &str) -> Result<VerifierKey, NoteError> {
        let (name, rest) = vkey
            .split_once('+')
            .ok_or(NoteError::VerifierKey("expected <name>+<key id>+<key>"))?;
        let (id_hex, key_b64) = rest
            .split_once('+')
            .ok_or(NoteError::VerifierKey("expected <name>+<key id>+<key>"))?;
        if !is_valid_key_name(name) {
            return Err(NoteError::VerifierKey("invalid key name"));
        }
        let id: [u8; 4] = hex_decode_exact(id_hex)
            .map_err(|_| NoteError::VerifierKey("key id is not eight lowercase hex digits"))?;
        let raw = base64_decode(key_b64)
            .map_err(|_| NoteError::VerifierKey("key is not canonical base64"))?;
        let (&type_id, key) = raw
            .split_first()
            .ok_or(NoteError::VerifierKey("empty key"))?;
        let signature_type = SignatureType::from_id(type_id)
            .ok_or(NoteError::VerifierKey("unsupported signature type"))?;
        let public_key: [u8; 32] = key
            .try_into()
            .map_err(|_| NoteError::VerifierKey("Ed25519 public key is not 32 bytes"))?;
        let parsed = VerifierKey::new(name, signature_type, public_key)?;
        if parsed.key_id != id {
            return Err(NoteError::VerifierKey(
                "key id does not match the name, type and key",
            ));
        }
        Ok(parsed)
    }

    /// The vkey text.
    pub fn encode(&self) -> String {
        let mut raw = Vec::with_capacity(33);
        raw.push(self.signature_type.id());
        raw.extend_from_slice(&self.public_key);
        format!(
            "{}+{}+{}",
            self.name,
            hex_encode(&self.key_id),
            base64_encode(&raw)
        )
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn key_id(&self) -> [u8; 4] {
        self.key_id
    }

    pub fn signature_type(&self) -> SignatureType {
        self.signature_type
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// True if `sig` claims to be from this key: same name and key ID.
    pub fn matches(&self, sig: &NoteSignature) -> bool {
        sig.name == self.name && sig.key_id == self.key_id
    }

    /// Verify one signature line against a note body. False if the line
    /// is not from this key ([`matches`](VerifierKey::matches)), has the
    /// wrong length for the signature type, or does not verify.
    ///
    /// For `cosignature/v1` the signed message is
    /// [`cosignature_v1_message`] with the timestamp carried in the
    /// signature; read it with [`NoteSignature::cosignature_timestamp`]
    /// once this returns true.
    pub fn verify(&self, body: &str, sig: &NoteSignature) -> bool {
        if !self.matches(sig) || sig.signature.len() != self.signature_type.signature_len() {
            return false;
        }
        match self.signature_type {
            SignatureType::Ed25519 => {
                let s: &[u8; 64] = sig.signature[..].try_into().expect("length checked");
                ed25519::verify(&self.public_key, body.as_bytes(), s)
            }
            SignatureType::CosignatureV1 => {
                let ts: [u8; 8] = sig.signature[..8].try_into().expect("length checked");
                let prefix = cosignature_v1_message(u64::from_be_bytes(ts), "");
                let s: &[u8; 64] = sig.signature[8..].try_into().expect("length checked");
                ed25519::verify_parts(&self.public_key, &[prefix.as_bytes(), body.as_bytes()], s)
            }
        }
    }
}

impl fmt::Display for VerifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.encode())
    }
}

/// A configured key that signed a note.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedSignature {
    /// Index of the key in the `keys` slice given to [`verify_note`]: the
    /// first, if the slice holds equal copies of the key.
    pub key: usize,
    /// Index of the key's first signature line in [`Note::signatures`]. Any
    /// later line from the key is identical to it.
    pub signature: usize,
    /// For a `cosignature/v1` key, the signed timestamp (Unix seconds).
    /// It is not compared with any clock here; tlog-cosignature lets
    /// verifiers reject timestamps in the future, and that is the caller's
    /// policy.
    pub timestamp: Option<u64>,
}

/// Verify a note against configured keys, following the signed-note rules
/// (see the module documentation): unknown keys are ignored, every line from
/// a known key must verify, and at least one must.
///
/// Returns one entry per configured key that signed, in signature-line
/// order. Equal entries in `keys` count as one key. Errors, at the first
/// offending line, with [`NoteError::AmbiguousKey`] if the line matches two
/// distinct configured keys, [`NoteError::InvalidSignature`] if it is from
/// a known key and fails, and [`NoteError::RepeatedKey`] if it verifies but
/// differs from an earlier line of the same key; and with
/// [`NoteError::NoVerifiedSignature`] if no known key signed.
pub fn verify_note(note: &Note, keys: &[VerifierKey]) -> Result<Vec<VerifiedSignature>, NoteError> {
    let mut verified: Vec<VerifiedSignature> = Vec::new();
    for (index, sig) in note.signatures.iter().enumerate() {
        let mut matching = keys.iter().enumerate().filter(|(_, k)| k.matches(sig));
        let Some((key_index, key)) = matching.next() else {
            continue; // unknown key
        };
        if matching.any(|(_, other)| other != key) {
            return Err(NoteError::AmbiguousKey {
                name: sig.name.clone(),
                key_id: sig.key_id,
            });
        }
        if !key.verify(&note.body, sig) {
            return Err(NoteError::InvalidSignature {
                name: sig.name.clone(),
                key_id: sig.key_id,
            });
        }
        match verified.iter().find(|v| v.key == key_index) {
            None => verified.push(VerifiedSignature {
                key: key_index,
                signature: index,
                timestamp: match key.signature_type {
                    SignatureType::Ed25519 => None,
                    SignatureType::CosignatureV1 => sig.cosignature_timestamp(),
                },
            }),
            // Same name and key ID, so only the signature bytes can differ.
            Some(first) if note.signatures[first.signature].signature != sig.signature => {
                return Err(NoteError::RepeatedKey {
                    name: sig.name.clone(),
                    key_id: sig.key_id,
                });
            }
            Some(_) => {} // an identical repeated line
        }
    }
    if verified.is_empty() {
        return Err(NoteError::NoVerifiedSignature);
    }
    Ok(verified)
}

// ---------------------------------------------------------------------------
// Checkpoints
// ---------------------------------------------------------------------------

/// The note text of a tlog-checkpoint: a signed tree head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// The log's origin line. For Pragmatic Server, `pragmatic/<server
    /// name>`.
    pub origin: String,
    /// Number of leaves in the tree.
    pub tree_size: u64,
    /// RFC 6962 root hash of the tree at `tree_size` (see
    /// [`crate::merkle::root`]).
    pub root: [u8; 32],
    /// Extension lines, opaque and usually absent.
    pub extensions: Vec<String>,
}

/// Parse an ASCII decimal with no sign and no leading zeros.
fn parse_decimal(s: &str) -> Option<u64> {
    let canonical = match s.as_bytes() {
        [] => false,
        [b'0'] => true,
        [b'0', ..] => false,
        digits => digits.iter().all(u8::is_ascii_digit),
    };
    if canonical {
        s.parse().ok()
    } else {
        None
    }
}

/// A line that may appear in a checkpoint body: non-empty, no newline and
/// no control characters.
fn is_valid_line(line: &str) -> bool {
    !line.is_empty() && !line.chars().any(|c| c < ' ')
}

impl Checkpoint {
    /// Parse a checkpoint body (a note's text, such as [`Note::body`]):
    /// at least three non-empty lines, each ending in a newline. The origin
    /// may be any non-empty line, even one [`Checkpoint::encode`] refuses
    /// to write (see the module documentation).
    pub fn parse(body: &str) -> Result<Checkpoint, NoteError> {
        let text = body
            .strip_suffix('\n')
            .ok_or(NoteError::Checkpoint("text does not end in a newline"))?;
        if text.chars().any(is_forbidden_control) {
            return Err(NoteError::Checkpoint("control character"));
        }
        let lines: Vec<&str> = text.split('\n').collect();
        if lines.len() < 3 {
            return Err(NoteError::Checkpoint("fewer than three lines"));
        }
        if lines.iter().any(|l| l.is_empty()) {
            return Err(NoteError::Checkpoint("empty line"));
        }
        let tree_size = parse_decimal(lines[1]).ok_or(NoteError::Checkpoint(
            "tree size is not a canonical decimal u64",
        ))?;
        let root = base64_decode_exact::<32>(lines[2])
            .map_err(|_| NoteError::Checkpoint("root hash is not canonical base64 of 32 bytes"))?;
        Ok(Checkpoint {
            origin: lines[0].to_string(),
            tree_size,
            root,
            extensions: lines[3..].iter().map(|l| l.to_string()).collect(),
        })
    }

    /// The checkpoint body. Fails if the origin is not a tlog-cosignature
    /// origin ([`is_valid_origin`]), which strict witnesses would refuse to
    /// cosign, or if an extension line is empty or contains a newline or
    /// other control character, since the body would then not parse back
    /// to this value.
    pub fn encode(&self) -> Result<String, NoteError> {
        if !is_valid_origin(&self.origin) {
            return Err(NoteError::Checkpoint(
                "origin must be 1 to 255 bytes with no white space, '+' or control characters",
            ));
        }
        if !self.extensions.iter().all(|e| is_valid_line(e)) {
            return Err(NoteError::Checkpoint("invalid extension line"));
        }
        let mut out = format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.tree_size,
            base64_encode(&self.root)
        );
        for e in &self.extensions {
            out.push_str(e);
            out.push('\n');
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Json;

    fn hex32(s: &str) -> [u8; 32] {
        hex_decode_exact(s).unwrap()
    }

    // -- Vectors generated with Go's crypto/ed25519 (tests/fixtures/note) --

    struct FixtureKey {
        label: String,
        key: VerifierKey,
    }

    fn fixture() -> (Json, Vec<FixtureKey>) {
        let text = include_str!("../tests/fixtures/note/vectors.json");
        let doc = Json::parse(text).expect("vectors.json is strict JSON");
        let mut keys = Vec::new();
        for entry in doc.get("keys").and_then(Json::as_array).unwrap() {
            let s = |k: &str| entry.get(k).and_then(Json::as_str).unwrap();
            let key =
                VerifierKey::parse(s("vkey")).unwrap_or_else(|e| panic!("{}: {e}", s("vkey")));
            let ty = entry.get("type").and_then(Json::as_u8_strict).unwrap();
            assert_eq!(key.name(), s("name"));
            assert_eq!(key.signature_type().id(), ty);
            assert_eq!(hex_encode(&key.key_id()), s("key_id"));
            assert_eq!(key.public_key(), &hex32(s("public_key")));
            // The vkey round-trips and agrees with the constructor.
            assert_eq!(key.encode(), s("vkey"));
            assert_eq!(key.to_string(), s("vkey"));
            let built = VerifierKey::new(
                s("name"),
                SignatureType::from_id(ty).unwrap(),
                hex32(s("public_key")),
            )
            .unwrap();
            assert_eq!(built, key);
            keys.push(FixtureKey {
                label: s("label").to_string(),
                key,
            });
        }
        (doc, keys)
    }

    #[test]
    fn go_generated_vectors() {
        let (doc, keys) = fixture();
        assert_eq!(keys.len(), 5);
        let cases = doc.get("cases").and_then(Json::as_array).unwrap();
        assert_eq!(cases.len(), 19);
        for case in cases {
            let name = case.get("name").and_then(Json::as_str).unwrap();
            let text = case.get("note").and_then(Json::as_str).unwrap();
            let note = Note::parse(text).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(note.encode().unwrap(), text, "{name}: encode round trip");
            assert_eq!(Note::parse_bytes(text.as_bytes()).unwrap(), note);

            // The body as a checkpoint.
            match case.get("checkpoint").unwrap() {
                Json::Null => assert!(Checkpoint::parse(&note.body).is_err(), "{name}"),
                cp => {
                    let parsed = Checkpoint::parse(&note.body).unwrap();
                    assert_eq!(
                        parsed.origin,
                        cp.get("origin").and_then(Json::as_str).unwrap()
                    );
                    assert_eq!(
                        Some(parsed.tree_size),
                        cp.get("tree_size").and_then(Json::as_u64_strict)
                    );
                    assert_eq!(
                        base64_encode(&parsed.root),
                        cp.get("root").and_then(Json::as_str).unwrap()
                    );
                    let ext: Vec<&str> = cp
                        .get("extensions")
                        .and_then(Json::as_array)
                        .unwrap()
                        .iter()
                        .map(|e| e.as_str().unwrap())
                        .collect();
                    assert_eq!(parsed.extensions, ext, "{name}");
                    assert_eq!(parsed.encode().unwrap(), note.body, "{name}");
                }
            }

            // Verification against the trusted subset.
            let trusted: Vec<VerifierKey> = case
                .get("trusted")
                .and_then(Json::as_array)
                .unwrap()
                .iter()
                .map(|l| {
                    let label = l.as_str().unwrap();
                    keys.iter().find(|k| k.label == label).unwrap().key.clone()
                })
                .collect();
            let got = verify_note(&note, &trusted);
            match case.get("result").and_then(Json::as_str).unwrap() {
                "ok" => {
                    let got = got.unwrap_or_else(|e| panic!("{name}: {e}"));
                    let want: Vec<VerifiedSignature> = case
                        .get("verified")
                        .and_then(Json::as_array)
                        .unwrap()
                        .iter()
                        .map(|v| {
                            let label = v.get("key").and_then(Json::as_str).unwrap();
                            let key = trusted
                                .iter()
                                .position(|k| keys.iter().any(|f| f.label == label && &f.key == k))
                                .unwrap();
                            VerifiedSignature {
                                key,
                                signature: v.get("signature").and_then(Json::as_u64_strict).unwrap()
                                    as usize,
                                timestamp: v.get("timestamp").and_then(Json::as_u64_strict),
                            }
                        })
                        .collect();
                    assert_eq!(got, want, "{name}");
                    // Each verified line also checks on its own.
                    for v in &got {
                        let sig = &note.signatures[v.signature];
                        assert!(trusted[v.key].verify(&note.body, sig), "{name}");
                        assert_eq!(
                            v.timestamp,
                            match trusted[v.key].signature_type() {
                                SignatureType::Ed25519 => None,
                                SignatureType::CosignatureV1 => sig.cosignature_timestamp(),
                            }
                        );
                    }
                }
                "repeated_key" => {
                    assert!(
                        matches!(got, Err(NoteError::RepeatedKey { .. })),
                        "{name}: {got:?}"
                    );
                    // Every line from a trusted key verifies on its own, so
                    // the repeat alone is what rejects the note.
                    for sig in &note.signatures {
                        if let Some(k) = trusted.iter().find(|k| k.matches(sig)) {
                            assert!(k.verify(&note.body, sig), "{name}");
                        }
                    }
                }
                "invalid_signature" => {
                    assert!(
                        matches!(got, Err(NoteError::InvalidSignature { .. })),
                        "{name}: {got:?}"
                    );
                }
                "no_verified_signature" => {
                    assert_eq!(got, Err(NoteError::NoVerifiedSignature), "{name}");
                }
                other => panic!("{name}: unknown result {other}"),
            }
        }
    }

    #[test]
    fn signatures_do_not_survive_body_changes() {
        let (doc, keys) = fixture();
        let all: Vec<VerifierKey> = keys.iter().take(3).map(|k| k.key.clone()).collect();
        let case = &doc.get("cases").and_then(Json::as_array).unwrap()[1];
        let note = Note::parse(case.get("note").and_then(Json::as_str).unwrap()).unwrap();
        assert_eq!(verify_note(&note, &all).unwrap().len(), 3);
        // Change one character of the body: every trusted line now fails.
        let mut changed = note.clone();
        changed.body = changed.body.replacen("42", "43", 1);
        for sig in &note.signatures {
            for key in &all {
                assert!(!key.verify(&changed.body, sig));
            }
        }
        assert!(matches!(
            verify_note(&changed, &all),
            Err(NoteError::InvalidSignature { .. })
        ));
        // A cosignature is not a plain signature over the body, and a log
        // signature is not a cosignature.
        let log_sig = &note.signatures[0];
        let w1_sig = &note.signatures[1];
        assert!(!all[1].verify(&note.body, log_sig));
        assert!(!all[0].verify(&note.body, w1_sig));
    }

    #[test]
    fn duplicate_and_ambiguous_keys() {
        let (doc, keys) = fixture();
        let case = &doc.get("cases").and_then(Json::as_array).unwrap()[0];
        let note = Note::parse(case.get("note").and_then(Json::as_str).unwrap()).unwrap();
        let log = keys[0].key.clone();
        let other = keys[3].key.clone();

        // Equal keys are one key, reported at its first index: the CLI may
        // hold a witness key twice, built in and from --witness-key.
        let once = vec![VerifiedSignature {
            key: 0,
            signature: 0,
            timestamp: None,
        }];
        assert_eq!(
            verify_note(&note, &[log.clone(), log.clone()]),
            Ok(once.clone())
        );
        assert_eq!(
            verify_note(&note, &[log.clone(), other.clone(), log.clone()]),
            Ok(once)
        );

        // Distinct keys that share a name and key ID are ambiguous. A real
        // pair takes about 2^32 key generations to find, so these are built
        // directly: another public key under the log's name and key ID, and
        // the log's key registered with another signature type.
        let ambiguous: Result<Vec<VerifiedSignature>, NoteError> = Err(NoteError::AmbiguousKey {
            name: log.name().to_string(),
            key_id: log.key_id(),
        });
        let another_key = VerifierKey {
            public_key: *other.public_key(),
            ..log.clone()
        };
        let another_type = VerifierKey {
            signature_type: SignatureType::CosignatureV1,
            ..log.clone()
        };
        for impostor in [another_key, another_type] {
            assert_ne!(impostor, log);
            assert_eq!(
                verify_note(&note, &[log.clone(), impostor.clone()]),
                ambiguous
            );
            assert_eq!(
                verify_note(&note, &[impostor, log.clone(), log.clone()]),
                ambiguous
            );
        }
        // An ambiguous pair that no line uses is harmless.
        let other_impostor = VerifierKey {
            public_key: *log.public_key(),
            ..other.clone()
        };
        assert!(verify_note(&note, &[log, other, other_impostor]).is_ok());
    }

    #[test]
    fn repeated_key_must_sign_identical_lines() {
        let (doc, keys) = fixture();
        let cases = doc.get("cases").and_then(Json::as_array).unwrap();
        let note_of = |name: &str| {
            let case = cases
                .iter()
                .find(|c| c.get("name").and_then(Json::as_str) == Some(name))
                .unwrap();
            Note::parse(case.get("note").and_then(Json::as_str).unwrap()).unwrap()
        };
        let log = keys[0].key.clone();
        let w1 = keys[1].key.clone();
        let repeated = Err(NoteError::RepeatedKey {
            name: w1.name().to_string(),
            key_id: w1.key_id(),
        });
        // Two valid cosignatures from one witness at different times are
        // refused in either order, rather than reporting whichever time
        // comes first.
        let a = note_of("two different cosignatures from one witness");
        let mut b = a.clone();
        b.signatures.swap(1, 2);
        assert_ne!(a.signatures[1], a.signatures[2]);
        for note in [&a, &b] {
            assert!(w1.verify(&note.body, &note.signatures[1]));
            assert!(w1.verify(&note.body, &note.signatures[2]));
            assert_eq!(
                verify_note(note, &[log.clone(), w1.clone()]),
                repeated.clone()
            );
            // The rule applies to known keys only.
            assert_eq!(
                verify_note(note, std::slice::from_ref(&log)).unwrap().len(),
                1
            );
        }
        // An identical repeat is reported once, with its one timestamp.
        let same = note_of("repeated cosignature line is reported once");
        assert_eq!(same.signatures[0], same.signatures[2]);
        let got = verify_note(&same, &[w1, log]).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].timestamp, same.signatures[0].cosignature_timestamp());
    }

    // -- Go's sumdb/note test vectors (golang.org/x/mod/sumdb/note,
    //    note_test.go, BSD-style license) --

    const PETER_VKEY: &str = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW";
    const ENOCH_VKEY: &str = "EnochRoot+af0cfe78+ATtqJ7zOtqQtYqOo0CpvDXNlMhV3HeJDpjrASKGLWdop";
    const GO_TEXT: &str = "If you think cryptography is the answer to your problem,\n\
                           then you don't know what your problem is.\n";
    const PETER_SIG: &str = "\u{2014} PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n";
    const ENOCH_SIG: &str = "\u{2014} EnochRoot rwz+eBzmZa0SO3NbfRGzPCpDckykFXSdeX+MNtCOXm2/5n2tiOHp+vAF1aGrQ5ovTG01oOTGwnWLox33WWd1RvMc+QQ=\n";

    #[test]
    fn go_sumdb_note_vectors() {
        let peter = VerifierKey::parse(PETER_VKEY).unwrap();
        let enoch = VerifierKey::parse(ENOCH_VKEY).unwrap();
        assert_eq!(peter.key_id(), [0xc7, 0x4f, 0x20, 0xa3]);
        assert_eq!(peter.encode(), PETER_VKEY);

        let text = format!("{GO_TEXT}\n{PETER_SIG}{ENOCH_SIG}");
        let note = Note::parse(&text).unwrap();
        assert_eq!(note.body, GO_TEXT);
        assert_eq!(note.signatures.len(), 2);
        assert_eq!(note.signatures[0].key_id_u32(), 0xc74f20a3);
        assert_eq!(note.signatures[1].key_id_u32(), 0xaf0cfe78);
        assert_eq!(note.encode().unwrap(), text);

        // One verified, one unknown.
        let got = verify_note(&note, std::slice::from_ref(&peter)).unwrap();
        assert_eq!(
            got,
            vec![VerifiedSignature {
                key: 0,
                signature: 0,
                timestamp: None
            }]
        );
        // Both verified.
        let got = verify_note(&note, &[enoch.clone(), peter.clone()]).unwrap();
        assert_eq!(got.iter().map(|v| v.key).collect::<Vec<_>>(), vec![1, 0]);
        // Neither.
        assert_eq!(verify_note(&note, &[]), Err(NoteError::NoVerifiedSignature));
        // Duplicated verifier, used and unused. Go's VerifierList reports
        // the used one as an ambiguous key; here equal keys are one key,
        // reported at its first index (see duplicate_and_ambiguous_keys).
        let enoch_only = Note::parse(&format!("{GO_TEXT}\n{ENOCH_SIG}")).unwrap();
        assert_eq!(
            verify_note(&enoch_only, &[enoch.clone(), peter.clone(), enoch.clone()]),
            Ok(vec![VerifiedSignature {
                key: 0,
                signature: 0,
                timestamp: None
            }])
        );
        let peter_only = Note::parse(&format!("{GO_TEXT}\n{PETER_SIG}")).unwrap();
        assert!(verify_note(&peter_only, &[enoch.clone(), peter.clone(), enoch]).is_ok());

        // 100 signatures are accepted, 101 are not.
        let many = |n: usize| format!("{GO_TEXT}\n{}", PETER_SIG.repeat(n));
        let hundred = Note::parse(&many(100)).unwrap();
        assert_eq!(
            verify_note(&hundred, std::slice::from_ref(&peter))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            Note::parse(&many(101)),
            Err(NoteError::Malformed("too many signatures"))
        );

        // Bytes inserted into the signature: canonical base64, wrong length.
        let (head, tail) = PETER_SIG.split_at(60);
        let corrupted = format!("{GO_TEXT}\n{head}ABCD{tail}");
        assert_eq!(
            verify_note(
                &Note::parse(&corrupted).unwrap(),
                std::slice::from_ref(&peter)
            ),
            Err(NoteError::InvalidSignature {
                name: "PeterNeumann".into(),
                key_id: [0xc7, 0x4f, 0x20, 0xa3]
            })
        );
        // A different key ID makes the line unknown, not invalid.
        let wrong_id = format!("{GO_TEXT}\n{}", PETER_SIG.replace("x08g", "xxxx"));
        assert_eq!(
            verify_note(&Note::parse(&wrong_id).unwrap(), &[peter]),
            Err(NoteError::NoVerifiedSignature)
        );

        // Go's malformed messages.
        let bad = [
            GO_TEXT.to_string(),
            format!("{GO_TEXT}\n"),
            format!("{GO_TEXT}\n{}", &PETER_SIG[..PETER_SIG.len() - 1]),
            format!("\u{1}{GO_TEXT}\n{PETER_SIG}"),
            format!("{GO_TEXT}\n\u{2014} Bad Name x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM="),
            format!("{GO_TEXT}\n{PETER_SIG}Unexpected line.\n"),
        ];
        for text in &bad {
            assert!(
                matches!(Note::parse(text), Err(NoteError::Malformed(_))),
                "{text:?}"
            );
        }
        // Go's "\xff" case is invalid UTF-8.
        let mut bytes = vec![0xff];
        bytes.extend_from_slice(format!("{GO_TEXT}\n{PETER_SIG}").as_bytes());
        assert_eq!(
            Note::parse_bytes(&bytes),
            Err(NoteError::Malformed("not UTF-8"))
        );
    }

    #[test]
    fn go_sumdb_vkey_manglings_are_rejected() {
        assert!(VerifierKey::parse(PETER_VKEY).is_ok());
        let b = PETER_VKEY.as_bytes();
        for i in 0..=b.len() {
            for j in i + 1..=b.len() {
                if i == 0 && j == b.len() {
                    continue;
                }
                let s = std::str::from_utf8(&b[i..j]).unwrap();
                assert!(VerifierKey::parse(s).is_err(), "{s}");
            }
        }
        for i in 0..b.len() {
            let mut m = b.to_vec();
            m[i] += 1;
            let s = String::from_utf8(m).unwrap();
            assert!(VerifierKey::parse(&s).is_err(), "{s}");
        }
        // Wrong key length and unknown algorithm, with adjusted key IDs.
        for s in [
            "PeterNeumann+cc469956+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TWBADKEY==",
            "PeterNeumann+173116ae+ZRpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW",
        ] {
            assert!(VerifierKey::parse(s).is_err(), "{s}");
        }
    }

    // -- The examples in the C2SP specifications --

    #[test]
    fn c2sp_signed_note_example() {
        let key = VerifierKey::parse(
            "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k",
        )
        .unwrap();
        let note = Note::parse(
            "This is an example message.\n\n\u{2014} example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n",
        )
        .unwrap();
        assert_eq!(note.body, "This is an example message.\n");
        assert_eq!(verify_note(&note, &[key]).unwrap().len(), 1);
    }

    #[test]
    fn c2sp_checkpoint_example() {
        // tlog-checkpoint's example (the signing key is not published).
        let text = "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n\n\u{2014} example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=\n";
        let note = Note::parse(text).unwrap();
        let cp = Checkpoint::parse(&note.body).unwrap();
        assert_eq!(cp.origin, "example.com/behind-the-sofa");
        assert_eq!(cp.tree_size, 20852163);
        assert!(cp.extensions.is_empty());
        assert_eq!(cp.encode().unwrap(), note.body);
        // tlog-cosignature's example of the signed message.
        assert_eq!(
            cosignature_v1_message(1679315147, &note.body),
            "cosignature/v1\ntime 1679315147\nexample.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"
        );
    }

    /// A real checkpoint from the Go checksum database, fetched from
    /// `https://sum.golang.org/latest` on 2026-10-13, verified with the
    /// key built into the `go` command.
    #[test]
    fn sum_golang_org_checkpoint() {
        let key = VerifierKey::parse(
            "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
        )
        .unwrap();
        let text = include_str!("../tests/fixtures/note/sum.golang.org.note");
        let note = Note::parse(text).unwrap();
        assert_eq!(note.encode().unwrap(), text);
        let cp = Checkpoint::parse(&note.body).unwrap();
        assert_eq!(cp.origin, "go.sum database tree");
        assert_eq!(cp.tree_size, 68816444);
        assert_eq!(
            verify_note(&note, std::slice::from_ref(&key)).unwrap(),
            vec![VerifiedSignature {
                key: 0,
                signature: 0,
                timestamp: None
            }]
        );
        // Its origin parses but predates tlog-cosignature's origin rules,
        // so this crate would not write it.
        assert!(matches!(cp.encode(), Err(NoteError::Checkpoint(_))));
        // The same body with a different size no longer verifies.
        let mut forged = note.clone();
        forged.body = note.body.replacen("\n68816444\n", "\n68816445\n", 1);
        assert_eq!(
            Checkpoint::parse(&forged.body).unwrap().tree_size,
            cp.tree_size + 1
        );
        assert!(matches!(
            verify_note(&forged, &[key]),
            Err(NoteError::InvalidSignature { .. })
        ));
    }

    // -- Parsing details --

    #[test]
    fn note_split_and_malformed_inputs() {
        let sig = "\u{2014} a/b AAAAAAE=";
        // The text runs to the last blank line, and may contain blank lines.
        let n = Note::parse(&format!("x\n\ny\n\n{sig}\n")).unwrap();
        assert_eq!(n.body, "x\n\ny\n");
        assert_eq!(n.signatures[0].key_id, [0, 0, 0, 0]);
        assert_eq!(n.signatures[0].signature, vec![1]);
        let n = Note::parse(&format!("x\n\n\n{sig}\n")).unwrap();
        assert_eq!(n.body, "x\n\n");

        let malformed = [
            "".to_string(),
            "x\n".to_string(),
            "x\n\n".to_string(),
            format!("x\n\n{sig}"),                           // no final newline
            format!("x\n\n{sig}\n\n"),                       // blank line after signatures
            format!("x\n\n{sig}\n{sig}"),                    // second line unterminated
            format!("x\r\n\n{sig}\n"),                       // carriage return
            format!("x\t\n\n{sig}\n"),                       // tab
            "x\n\n- a/b AAAAAAE=\n".to_string(),             // hyphen, not em dash
            "x\n\n\u{2014}a/b AAAAAAE=\n".to_string(),       // no space after the dash
            "x\n\n\u{2014}  AAAAAAE=\n".to_string(),         // empty name
            "x\n\n\u{2014} a+b AAAAAAE=\n".to_string(),      // '+' in name
            "x\n\n\u{2014} a\u{a0}b AAAAAAE=\n".to_string(), // NBSP in name
            "x\n\n\u{2014} a/b\n".to_string(),               // no signature
            "x\n\n\u{2014} a/b AAAAAAF=\n".to_string(),      // non-canonical base64
            "x\n\n\u{2014} a/b AAAAAAE\n".to_string(),       // unpadded
            "x\n\n\u{2014} a/b  AAAAAAE=\n".to_string(),     // two spaces
            "x\n\n\u{2014} a/b AAAAAA==\n".to_string(),      // key ID only
            "x\n\n\u{2014} a/b AAAAAAE= \n".to_string(),     // trailing space
        ];
        for text in &malformed {
            assert!(
                matches!(Note::parse(text), Err(NoteError::Malformed(_))),
                "{text:?}"
            );
        }
    }

    #[test]
    fn note_encode_refuses_unparseable_notes() {
        let sig = NoteSignature {
            name: "a/b".into(),
            key_id: [1, 2, 3, 4],
            signature: vec![5],
        };
        let ok = Note {
            body: "x\n".into(),
            signatures: vec![sig.clone()],
        };
        assert_eq!(ok.encode().unwrap(), "x\n\n\u{2014} a/b AQIDBAU=\n");
        assert_eq!(Note::parse(&ok.encode().unwrap()).unwrap(), ok);
        let bad = [
            Note {
                body: "x".into(),
                ..ok.clone()
            },
            Note {
                body: "x\r\n".into(),
                ..ok.clone()
            },
            Note {
                signatures: vec![],
                ..ok.clone()
            },
            Note {
                signatures: vec![sig.clone(); MAX_SIGNATURES + 1],
                ..ok.clone()
            },
            Note {
                signatures: vec![NoteSignature {
                    name: "a b".into(),
                    ..sig.clone()
                }],
                ..ok.clone()
            },
            Note {
                signatures: vec![NoteSignature {
                    signature: vec![],
                    ..sig.clone()
                }],
                ..ok.clone()
            },
        ];
        for note in &bad {
            assert!(note.encode().is_err(), "{note:?}");
        }
    }

    #[test]
    fn signature_lines() {
        let line = "\u{2014} witness.example/one AAAAAQAAAABo2+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
        let sig = NoteSignature::parse_line(line).unwrap();
        assert_eq!(sig.name, "witness.example/one");
        assert_eq!(sig.key_id_u32(), 1);
        assert_eq!(sig.signature.len(), 72);
        assert_eq!(sig.cosignature_timestamp(), Some(1_759_240_192));
        assert_eq!(sig.to_line().unwrap(), line);
        // A plain Ed25519 length has no timestamp.
        let plain = NoteSignature {
            signature: vec![0; 64],
            ..sig.clone()
        };
        assert_eq!(plain.cosignature_timestamp(), None);
        assert!(NoteSignature::parse_line(&format!("{line}\n")).is_err());
    }

    #[test]
    fn checkpoint_parse_and_encode() {
        let root = [0xabu8; 32];
        let b64 = base64_encode(&root);
        let cp = Checkpoint::parse(&format!("o\n18446744073709551615\n{b64}\na b\n+\n")).unwrap();
        assert_eq!(cp.tree_size, u64::MAX);
        assert_eq!(cp.root, root);
        assert_eq!(cp.extensions, vec!["a b", "+"]);
        assert_eq!(
            cp.encode().unwrap(),
            format!("o\n18446744073709551615\n{b64}\na b\n+\n")
        );
        assert_eq!(
            Checkpoint::parse(&format!("o\n0\n{b64}\n"))
                .unwrap()
                .tree_size,
            0
        );

        let short = base64_encode(&[0u8; 31]);
        let bad = [
            format!("o\n42\n{b64}"),     // no final newline
            "o\n42\n".to_string(),       // two lines
            format!("o\n42\n{b64}\n\n"), // empty extension
            format!("\n42\n{b64}\n"),    // empty origin
            format!("o\n042\n{b64}\n"),  // leading zero
            format!("o\n00\n{b64}\n"),
            format!("o\n+42\n{b64}\n"),
            format!("o\n-1\n{b64}\n"),
            format!("o\n4 2\n{b64}\n"),
            format!("o\n\u{664}\n{b64}\n"), // Arabic-Indic digit
            format!("o\n18446744073709551616\n{b64}\n"), // u64 overflow
            format!("o\n42\n{short}\n"),    // 31-byte root
            format!("o\n42\n{}\n", hex_encode(&root)), // hex root
            format!("o\n42\n{}\n", b64.trim_end_matches('=')),
            format!("o\r\n42\n{b64}\n"),
        ];
        for body in &bad {
            assert!(
                matches!(Checkpoint::parse(body), Err(NoteError::Checkpoint(_))),
                "{body:?}"
            );
        }

        let mut cp = Checkpoint {
            origin: "pragmatic/example".into(),
            tree_size: 1,
            root,
            extensions: vec![],
        };
        assert!(cp.encode().is_ok());
        // The encoder holds origins to tlog-cosignature: at most 255 bytes,
        // no Unicode white space, no '+' and no control characters. The
        // parser reads every one of these back except the first three.
        let long = "o".repeat(MAX_ORIGIN_LEN + 1);
        for origin in [
            "",
            "a\nb",
            "a\rb",
            "pragmatic/my server",
            "pragmatic/server+x",
            "a\tb",
            "a\u{a0}b",
            "a\u{3000}b",
            "go.sum database tree",
            &long,
        ] {
            cp.origin = origin.into();
            assert!(
                matches!(cp.encode(), Err(NoteError::Checkpoint(_))),
                "{origin:?}"
            );
            assert!(!is_valid_origin(origin), "{origin:?}");
        }
        cp.origin = "o".repeat(MAX_ORIGIN_LEN);
        assert!(cp.encode().is_ok());
        // Multi-byte characters count in bytes: 128 two-byte letters is 256.
        cp.origin = "\u{e9}".repeat(128);
        assert!(cp.encode().is_err());
        cp.origin = "\u{e9}".repeat(127);
        assert!(cp.encode().is_ok());
        // Parsing stays lenient about the origin, as the module explains.
        let parsed = Checkpoint::parse(&format!("{long}\n1\n{b64}\n")).unwrap();
        assert_eq!(parsed.origin, long);
        cp.origin = "o".into();
        cp.extensions = vec![String::new()];
        assert!(cp.encode().is_err());
    }

    #[test]
    fn verifier_keys() {
        let pk = hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let log = VerifierKey::new("pragmatic/example", SignatureType::Ed25519, pk).unwrap();
        let wit = VerifierKey::new("pragmatic/example", SignatureType::CosignatureV1, pk).unwrap();
        // The type byte is part of the key ID.
        assert_ne!(log.key_id(), wit.key_id());
        assert_eq!(
            log.key_id(),
            key_id("pragmatic/example", SignatureType::Ed25519, &pk)
        );
        for key in [&log, &wit] {
            assert_eq!(&VerifierKey::parse(&key.encode()).unwrap(), key);
        }
        assert!(wit.encode().contains("+BN"), "type 0x04 encodes as 'B...'");

        // Invalid names and keys.
        for name in ["", "a b", "a+b", "a\tb", "a\u{3000}b"] {
            assert!(
                VerifierKey::new(name, SignatureType::Ed25519, pk).is_err(),
                "{name:?}"
            );
        }
        let identity = hex32("0100000000000000000000000000000000000000000000000000000000000000");
        assert!(VerifierKey::new("a", SignatureType::Ed25519, identity).is_err());
        let off_curve = {
            let mut b = [0u8; 32];
            b[0] = 2;
            b
        };
        assert!(VerifierKey::new("a", SignatureType::Ed25519, off_curve).is_err());

        // A cosigner name is at most 255 bytes, whether the key is built or
        // parsed. A plain Ed25519 note key's name has no length limit.
        let max = "w".repeat(MAX_ORIGIN_LEN);
        let long = "w".repeat(MAX_ORIGIN_LEN + 1);
        let cosigner = VerifierKey::new(&max, SignatureType::CosignatureV1, pk).unwrap();
        assert_eq!(VerifierKey::parse(&cosigner.encode()).unwrap(), cosigner);
        assert_eq!(
            VerifierKey::new(&long, SignatureType::CosignatureV1, pk),
            Err(NoteError::VerifierKey(
                "cosigner name is longer than 255 bytes"
            ))
        );
        let mut raw = vec![SignatureType::CosignatureV1.id()];
        raw.extend_from_slice(&pk);
        let long_vkey = format!(
            "{long}+{}+{}",
            hex_encode(&key_id(&long, SignatureType::CosignatureV1, &pk)),
            base64_encode(&raw)
        );
        assert_eq!(
            VerifierKey::parse(&long_vkey),
            Err(NoteError::VerifierKey(
                "cosigner name is longer than 255 bytes"
            ))
        );
        let long_plain = VerifierKey::new(&long, SignatureType::Ed25519, pk).unwrap();
        assert_eq!(
            VerifierKey::parse(&long_plain.encode()).unwrap(),
            long_plain
        );

        // Uppercase key IDs are not canonical hex.
        let upper = PETER_VKEY.replace("c74f20a3", "C74F20A3");
        assert_eq!(
            VerifierKey::parse(&upper),
            Err(NoteError::VerifierKey(
                "key id is not eight lowercase hex digits"
            ))
        );
        // Unsupported types, with a consistent key ID.
        for ty in [0x00u8, 0x02, 0x03, 0x05, 0x06, 0xff] {
            let mut raw = vec![ty];
            raw.extend_from_slice(&pk);
            let mut h = Sha256::new();
            h.update(b"a\n");
            h.update(&raw);
            let id = h.finalize();
            let vkey = format!("a+{}+{}", hex_encode(&id[..4]), base64_encode(&raw));
            assert_eq!(
                VerifierKey::parse(&vkey),
                Err(NoteError::VerifierKey("unsupported signature type")),
                "{ty}"
            );
        }
    }

    #[test]
    fn error_messages() {
        assert_eq!(
            NoteError::InvalidSignature {
                name: "PeterNeumann".into(),
                key_id: [0xc7, 0x4f, 0x20, 0xa3]
            }
            .to_string(),
            "invalid signature for key PeterNeumann+c74f20a3"
        );
        assert_eq!(
            NoteError::RepeatedKey {
                name: "witness.example/one".into(),
                key_id: [0xfb, 0x78, 0x3f, 0xf6]
            }
            .to_string(),
            "two different signatures for key witness.example/one+fb783ff6"
        );
        assert_eq!(
            NoteError::NoVerifiedSignature.to_string(),
            "note has no verifiable signatures"
        );
        assert_eq!(
            NoteError::Malformed("too many signatures").to_string(),
            "malformed note: too many signatures"
        );
    }
}
