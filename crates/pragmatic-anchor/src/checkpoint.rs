//! Checkpoints: the signed tree head that ends every anchoring batch
//! (design 4.7), the server's Ed25519 log key, and key rotation records.
//!
//! A checkpoint is the C2SP `tlog-checkpoint` body
//!
//! ```text
//! <origin>\n<tree size, decimal>\n<base64 root>\n
//! ```
//!
//! signed as a C2SP `signed-note` by the server's Ed25519 key. The key's
//! name in the note is the log's origin, `pragmatic/<server name>`, and its
//! key id is `SHA-256(name ‖ 0x0A ‖ 0x01 ‖ public key)[:4]`, the signed-note
//! recommendation, so Go's `sumdb/note`, Sigstore tooling and the public
//! witness network can all verify Pragmatic checkpoints with a standard
//! vkey.
//!
//! Formatting and verification are the core's ([`pragmatic::note`]); this
//! module adds only what needs a private key. Witnesses timestamp
//! `anchor_digest = SHA-256(body)`, the body alone, so signatures and
//! cosignatures can be added to the note later without changing what was
//! anchored.
//!
//! # Key files
//!
//! Keys are stored in the format of Go's `golang.org/x/mod/sumdb/note`
//! (`PRIVATE+KEY+<name>+<key id hex>+<base64(type ‖ seed)>`), so a key made
//! by `note.GenerateKey` works here and the other way round. The key file
//! is a secret; [`LogSigner`]'s `Debug` output never shows it.

use ed25519_dalek::{Signer as _, SigningKey};
use pragmatic::ed25519;
use pragmatic::encoding::{base64_decode, base64_encode, hex_decode_exact, hex_encode};
use pragmatic::json::Json;
use pragmatic::note::{self, Checkpoint, Note, NoteSignature, SignatureType, VerifierKey};
use pragmatic::sha256::{sha256, Digest};

use crate::error::AnchorError;

/// The prefix of a private key in the Go `note` format.
const SKEY_PREFIX: &str = "PRIVATE+KEY+";

/// The origin of a Pragmatic Server's log: `pragmatic/<server name>`.
pub fn origin_for(server_name: &str) -> String {
    format!("pragmatic/{server_name}")
}

/// `anchor_digest = SHA-256(checkpoint body)`: what RFC 3161 witnesses
/// timestamp.
pub fn anchor_digest(body: &str) -> Digest {
    sha256(body.as_bytes())
}

/// An Ed25519 signing key with the note key name it signs under. Used for
/// the log key (signature type `0x01`) and, through
/// [`crate::witness::Cosigner`], for witness keys (type `0x04`).
pub struct NoteSigner {
    name: String,
    signature_type: SignatureType,
    key: SigningKey,
    key_id: [u8; 4],
}

impl std::fmt::Debug for NoteSigner {
    /// The name and key id only, never key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoteSigner")
            .field("name", &self.name)
            .field("type", &self.signature_type)
            .field("key_id", &hex_encode(&self.key_id))
            .finish()
    }
}

impl NoteSigner {
    /// A signer for `name` from a 32-byte Ed25519 seed. The name must be a
    /// valid note key name, and a cosigner's must also be a valid origin.
    pub fn from_seed(
        name: &str,
        signature_type: SignatureType,
        seed: [u8; 32],
    ) -> Result<NoteSigner, AnchorError> {
        let key = SigningKey::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        // VerifierKey::new applies every name and point rule the verifiers
        // apply, so a signer can never produce lines its own vkey rejects.
        let vkey = VerifierKey::new(name, signature_type, public)?;
        Ok(NoteSigner {
            name: name.to_string(),
            signature_type,
            key,
            key_id: vkey.key_id(),
        })
    }

    /// A fresh signer with a seed from the operating system's CSPRNG.
    pub fn generate(name: &str, signature_type: SignatureType) -> Result<NoteSigner, AnchorError> {
        let mut seed = [0u8; 32];
        pragmatic::rand::fill(&mut seed).map_err(AnchorError::io("reading the OS CSPRNG"))?;
        NoteSigner::from_seed(name, signature_type, seed)
    }

    /// Parse a private key in the Go `note` format. The key id must match
    /// the name, type and public key.
    pub fn parse_skey(skey: &str) -> Result<NoteSigner, AnchorError> {
        let bad = |why: &str| AnchorError::Key(why.to_string());
        let rest = skey
            .trim_end_matches(['\n', '\r'])
            .strip_prefix(SKEY_PREFIX)
            .ok_or_else(|| bad("not a PRIVATE+KEY+ line"))?;
        let (name, rest) = rest.split_once('+').ok_or_else(|| bad("missing key id"))?;
        let (id_hex, key_b64) = rest.split_once('+').ok_or_else(|| bad("missing key"))?;
        let id: [u8; 4] = hex_decode_exact(id_hex)
            .map_err(|_| bad("key id is not eight lowercase hex digits"))?;
        let raw = base64_decode(key_b64).map_err(|_| bad("key is not canonical base64"))?;
        let (&type_id, seed) = raw.split_first().ok_or_else(|| bad("empty key"))?;
        let signature_type =
            SignatureType::from_id(type_id).ok_or_else(|| bad("unsupported key type"))?;
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| bad("Ed25519 seed is not 32 bytes"))?;
        let signer = NoteSigner::from_seed(name, signature_type, seed)?;
        if signer.key_id != id {
            return Err(bad("key id does not match the name and key"));
        }
        Ok(signer)
    }

    /// The private key in the Go `note` format. A secret: write it only to
    /// a file readable by the server.
    pub fn encode_skey(&self) -> String {
        let mut raw = Vec::with_capacity(33);
        raw.push(self.signature_type.id());
        raw.extend_from_slice(&self.key.to_bytes());
        format!(
            "{SKEY_PREFIX}{}+{}+{}",
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

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// The verifier key (vkey) for this signer, to publish and to pin.
    pub fn verifier_key(&self) -> VerifierKey {
        VerifierKey::new(&self.name, self.signature_type, self.public_key())
            .expect("checked at construction")
    }

    /// A raw Ed25519 signature over `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }

    /// A note signature line object for `signature_bytes`.
    pub(crate) fn note_signature(&self, signature: Vec<u8>) -> NoteSignature {
        NoteSignature {
            name: self.name.clone(),
            key_id: self.key_id,
            signature,
        }
    }
}

/// The server's log key: signs checkpoints as signed notes under the log's
/// origin.
#[derive(Debug)]
pub struct LogSigner(NoteSigner);

impl LogSigner {
    /// A log key for `origin` (see [`origin_for`]) from a 32-byte seed.
    pub fn from_seed(origin: &str, seed: [u8; 32]) -> Result<LogSigner, AnchorError> {
        if !note::is_valid_origin(origin) {
            return Err(AnchorError::Key(format!(
                "{origin:?} is not a valid checkpoint origin"
            )));
        }
        Ok(LogSigner(NoteSigner::from_seed(
            origin,
            SignatureType::Ed25519,
            seed,
        )?))
    }

    /// A fresh log key for `origin` (`keygen`).
    pub fn generate(origin: &str) -> Result<LogSigner, AnchorError> {
        let mut seed = [0u8; 32];
        pragmatic::rand::fill(&mut seed).map_err(AnchorError::io("reading the OS CSPRNG"))?;
        LogSigner::from_seed(origin, seed)
    }

    /// Parse the key file (Go `note` private key format, type `0x01`).
    pub fn parse_skey(skey: &str) -> Result<LogSigner, AnchorError> {
        let signer = NoteSigner::parse_skey(skey)?;
        if signer.signature_type != SignatureType::Ed25519 {
            return Err(AnchorError::Key(
                "a log key must be an Ed25519 note key".into(),
            ));
        }
        if !note::is_valid_origin(&signer.name) {
            return Err(AnchorError::Key(
                "the key name is not a valid origin".into(),
            ));
        }
        Ok(LogSigner(signer))
    }

    /// The key file contents. A secret.
    pub fn encode_skey(&self) -> String {
        self.0.encode_skey()
    }

    /// The log's origin, which is also the key name.
    pub fn origin(&self) -> &str {
        self.0.name()
    }

    pub fn key_id(&self) -> [u8; 4] {
        self.0.key_id()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.public_key()
    }

    /// The vkey auditors pin (`--log-key`) and witnesses configure.
    pub fn verifier_key(&self) -> VerifierKey {
        self.0.verifier_key()
    }

    /// A raw signature over `message` (bundle signatures, rotation
    /// records, backup manifests).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message)
    }

    /// Sign the checkpoint for a tree of `tree_size` leaves with `root`.
    pub fn sign_checkpoint(
        &self,
        tree_size: u64,
        root: Digest,
    ) -> Result<SignedCheckpoint, AnchorError> {
        let checkpoint = Checkpoint {
            origin: self.origin().to_string(),
            tree_size,
            root,
            extensions: Vec::new(),
        };
        let body = checkpoint.encode()?;
        let signature = self.0.sign(body.as_bytes()).to_vec();
        let note = Note {
            body: body.clone(),
            signatures: vec![self.0.note_signature(signature)],
        }
        .encode()?;
        Ok(SignedCheckpoint {
            anchor_digest: anchor_digest(&body),
            checkpoint,
            body,
            note,
        })
    }
}

/// A checkpoint with its signed note text and anchor digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    /// The checkpoint body (the note text).
    pub body: String,
    /// The signed note: body, blank line, signature lines.
    pub note: String,
    /// `SHA-256(body)`.
    pub anchor_digest: Digest,
}

impl SignedCheckpoint {
    /// Read a signed checkpoint note. Signatures are parsed, not verified;
    /// use [`SignedCheckpoint::verify`] with a pinned key.
    pub fn parse(note_text: &str) -> Result<SignedCheckpoint, AnchorError> {
        let parsed = Note::parse(note_text)?;
        let checkpoint = Checkpoint::parse(&parsed.body)?;
        Ok(SignedCheckpoint {
            anchor_digest: anchor_digest(&parsed.body),
            checkpoint,
            body: parsed.body,
            note: note_text.to_string(),
        })
    }

    /// True if `key` signed this checkpoint (signed-note rules, through the
    /// core verifier).
    pub fn verify(&self, key: &VerifierKey) -> bool {
        Note::parse(&self.note)
            .ok()
            .is_some_and(|n| note::verify_note(&n, std::slice::from_ref(key)).is_ok())
    }
}

/// One entry of `GET /v1/keys`: a log key and its validity window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    pub key_id: [u8; 4],
    pub public_key: [u8; 32],
    /// Unix seconds from which the key signs.
    pub not_before: u64,
    /// Unix seconds at which the key was rotated out, or `None` for the
    /// current key.
    pub not_after: Option<u64>,
}

impl KeyInfo {
    /// `{key_id, public_key, not_before, not_after}` with hex keys and
    /// `null` for a current key.
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("key_id".into(), hex_encode(&self.key_id).into()),
            ("public_key".into(), hex_encode(&self.public_key).into()),
            ("not_before".into(), self.not_before.into()),
            (
                "not_after".into(),
                self.not_after.map_or(Json::Null, Json::from),
            ),
        ])
    }
}

/// The domain line of the message both keys sign in a rotation.
const ROTATE_DOMAIN: &str = "pragmatic/v2/key-rotate\n";

/// A `key.rotate` record (design 4.7): the old and the new log key each
/// sign the handover, so a verifier holding either key can follow the
/// chain of keys, and neither key alone can claim a successor.
///
/// The server appends [`KeyRotation::to_json`] to the access log as the
/// data of a `key.rotate` note; this type only builds and checks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRotation {
    pub old_key_id: [u8; 4],
    pub old_public_key: [u8; 32],
    pub new_key_id: [u8; 4],
    pub new_public_key: [u8; 32],
    /// Unix seconds of the rotation.
    pub at: u64,
    pub old_signature: [u8; 64],
    pub new_signature: [u8; 64],
}

impl KeyRotation {
    /// Sign a rotation from `old` to `new` at `at` (Unix seconds).
    pub fn sign(old: &LogSigner, new: &LogSigner, at: u64) -> KeyRotation {
        let mut r = KeyRotation {
            old_key_id: old.key_id(),
            old_public_key: old.public_key(),
            new_key_id: new.key_id(),
            new_public_key: new.public_key(),
            at,
            old_signature: [0; 64],
            new_signature: [0; 64],
        };
        let msg = r.message();
        r.old_signature = old.sign(&msg);
        r.new_signature = new.sign(&msg);
        r
    }

    /// The signed message: a domain line, then the canonical JSON of the
    /// unsigned fields.
    pub fn message(&self) -> Vec<u8> {
        let fields = Json::Object(self.unsigned_fields());
        format!("{ROTATE_DOMAIN}{}", fields.canonical_string()).into_bytes()
    }

    fn unsigned_fields(&self) -> Vec<(String, Json)> {
        vec![
            ("at".into(), self.at.into()),
            ("new_key_id".into(), hex_encode(&self.new_key_id).into()),
            (
                "new_public_key".into(),
                hex_encode(&self.new_public_key).into(),
            ),
            ("old_key_id".into(), hex_encode(&self.old_key_id).into()),
            (
                "old_public_key".into(),
                hex_encode(&self.old_public_key).into(),
            ),
        ]
    }

    /// True if both signatures verify (with the core's strict RFC 8032
    /// verifier) and each key id matches its public key under the same key
    /// name, `origin`.
    pub fn verify(&self, origin: &str) -> bool {
        let msg = self.message();
        let id = |pk: &[u8; 32]| note::key_id(origin, SignatureType::Ed25519, pk);
        id(&self.old_public_key) == self.old_key_id
            && id(&self.new_public_key) == self.new_key_id
            && ed25519::verify(&self.old_public_key, &msg, &self.old_signature)
            && ed25519::verify(&self.new_public_key, &msg, &self.new_signature)
    }

    /// The record as note data: the unsigned fields plus both signatures,
    /// hex.
    pub fn to_json(&self) -> Json {
        let mut fields = self.unsigned_fields();
        fields.push((
            "new_signature".into(),
            hex_encode(&self.new_signature).into(),
        ));
        fields.push((
            "old_signature".into(),
            hex_encode(&self.old_signature).into(),
        ));
        Json::Object(fields)
    }

    /// Read a record written by [`KeyRotation::to_json`]. Unknown or
    /// missing keys are errors; signatures are not checked here.
    pub fn from_json(doc: &Json) -> Result<KeyRotation, AnchorError> {
        let members = doc
            .as_object()
            .ok_or_else(|| AnchorError::Json("key.rotate is not an object".into()))?;
        const KEYS: [&str; 7] = [
            "at",
            "new_key_id",
            "new_public_key",
            "new_signature",
            "old_key_id",
            "old_public_key",
            "old_signature",
        ];
        if members.len() != KEYS.len() || members.iter().any(|(k, _)| !KEYS.contains(&k.as_str())) {
            return Err(AnchorError::Json("key.rotate has unexpected keys".into()));
        }
        Ok(KeyRotation {
            at: json_u64(doc, "at")?,
            new_key_id: json_hex(doc, "new_key_id")?,
            new_public_key: json_hex(doc, "new_public_key")?,
            new_signature: json_hex(doc, "new_signature")?,
            old_key_id: json_hex(doc, "old_key_id")?,
            old_public_key: json_hex(doc, "old_public_key")?,
            old_signature: json_hex(doc, "old_signature")?,
        })
    }
}

/// A strict unsigned integer member.
pub(crate) fn json_u64(doc: &Json, key: &str) -> Result<u64, AnchorError> {
    doc.get(key)
        .and_then(Json::as_u64_strict)
        .ok_or_else(|| AnchorError::Json(format!("{key} is not an unsigned integer")))
}

/// A string member.
pub(crate) fn json_str<'a>(doc: &'a Json, key: &str) -> Result<&'a str, AnchorError> {
    doc.get(key)
        .and_then(Json::as_str)
        .ok_or_else(|| AnchorError::Json(format!("{key} is not a string")))
}

/// A lowercase hex member of exactly `N` bytes.
pub(crate) fn json_hex<const N: usize>(doc: &Json, key: &str) -> Result<[u8; N], AnchorError> {
    hex_decode_exact(json_str(doc, key)?)
        .map_err(|_| AnchorError::Json(format!("{key} is not {N} bytes of lowercase hex")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pragmatic::note::verify_note;

    fn signer() -> LogSigner {
        LogSigner::from_seed("pragmatic/test", [1u8; 32]).unwrap()
    }

    #[test]
    fn checkpoint_is_a_c2sp_signed_note() {
        let s = signer();
        let root = [7u8; 32];
        let signed = s.sign_checkpoint(9001, root).unwrap();
        let expected_body = format!("pragmatic/test\n9001\n{}\n", base64_encode(&root));
        assert_eq!(signed.body, expected_body);
        assert_eq!(signed.anchor_digest, sha256(expected_body.as_bytes()));
        // One signature line from the log key, under the origin as name.
        let note = Note::parse(&signed.note).unwrap();
        assert_eq!(note.body, expected_body);
        assert_eq!(note.signatures.len(), 1);
        assert_eq!(note.signatures[0].name, "pragmatic/test");
        // Key id = SHA-256(name ‖ 0x0A ‖ 0x01 ‖ public key)[:4].
        let mut pre = b"pragmatic/test\n\x01".to_vec();
        pre.extend_from_slice(&s.public_key());
        assert_eq!(s.key_id(), sha256(&pre)[..4]);
        assert_eq!(note.signatures[0].key_id, s.key_id());
        // The core's signed-note verifier accepts it with the vkey, and the
        // vkey round-trips through its text form.
        let vkey = VerifierKey::parse(&s.verifier_key().encode()).unwrap();
        assert!(verify_note(&note, std::slice::from_ref(&vkey)).is_ok());
        assert!(signed.verify(&vkey));
        let reparsed = SignedCheckpoint::parse(&signed.note).unwrap();
        assert_eq!(reparsed, signed);
        // A different key does not verify it.
        let other = LogSigner::from_seed("pragmatic/test", [2u8; 32]).unwrap();
        assert!(!signed.verify(&other.verifier_key()));
    }

    #[test]
    fn skey_round_trips_in_the_go_note_format() {
        let s = signer();
        let skey = s.encode_skey();
        assert!(skey.starts_with("PRIVATE+KEY+pragmatic/test+"));
        let back = LogSigner::parse_skey(&format!("{skey}\n")).unwrap();
        assert_eq!(back.public_key(), s.public_key());
        assert_eq!(back.key_id(), s.key_id());
        // Debug never shows the key.
        assert!(!format!("{back:?}").contains(&skey[skey.len() - 20..]));
        // A wrong key id, wrong type or junk is refused.
        let tampered = skey.replacen(&hex_encode(&s.key_id()), "00000000", 1);
        assert!(LogSigner::parse_skey(&tampered).is_err());
        let cosigner = NoteSigner::from_seed("w", SignatureType::CosignatureV1, [3; 32]).unwrap();
        assert!(LogSigner::parse_skey(&cosigner.encode_skey()).is_err());
        assert!(LogSigner::parse_skey("PRIVATE+KEY+x").is_err());
        assert!(LogSigner::from_seed("has space", [0; 32]).is_err());
    }

    /// The Go `note` package's own example key, so key files made by Go
    /// tooling are read the same way.
    #[test]
    fn reads_the_go_note_example_key() {
        let skey = "PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz";
        let vkey = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW";
        let s = NoteSigner::parse_skey(skey).unwrap();
        assert_eq!(s.verifier_key().encode(), vkey);
        assert_eq!(s.encode_skey(), skey);
    }

    #[test]
    fn rotation_is_signed_by_both_keys() {
        let old = signer();
        let new = LogSigner::from_seed("pragmatic/test", [9u8; 32]).unwrap();
        let r = KeyRotation::sign(&old, &new, 1_760_000_000);
        assert!(r.verify("pragmatic/test"));
        let back = KeyRotation::from_json(&Json::parse(&r.to_json().to_string()).unwrap()).unwrap();
        assert_eq!(back, r);
        assert!(back.verify("pragmatic/test"));
        // Any field change breaks it, and so does a different origin.
        let mut bad = r.clone();
        bad.at += 1;
        assert!(!bad.verify("pragmatic/test"));
        let mut swapped = r.clone();
        swapped.new_signature = r.old_signature;
        assert!(!swapped.verify("pragmatic/test"));
        assert!(!r.verify("pragmatic/other"));
        // Unknown keys are refused.
        let mut doc = r.to_json();
        if let Json::Object(m) = &mut doc {
            m.push(("extra".into(), Json::Null));
        }
        assert!(KeyRotation::from_json(&doc).is_err());
    }

    #[test]
    fn key_info_json() {
        let k = KeyInfo {
            key_id: [1, 2, 3, 4],
            public_key: [0; 32],
            not_before: 5,
            not_after: None,
        };
        assert_eq!(
            k.to_json().to_string(),
            format!(
                "{{\"key_id\":\"01020304\",\"public_key\":\"{}\",\"not_before\":5,\"not_after\":null}}",
                "0".repeat(64)
            )
        );
    }
}
