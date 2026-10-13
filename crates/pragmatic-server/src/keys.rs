//! The server's keys (design 4.1, 4.7, 4.8 and 4.13): the log key that
//! signs checkpoints, evidence bundles and backup manifests, the witness
//! key that cosigns other logs' checkpoints in witness mode, the anchor key
//! behind HMAC run ids, and the key ring that `GET /v1/keys` serves.
//!
//! # The log key
//!
//! The log key is a C2SP signed-note key, kept in the private key format of
//! Go's `golang.org/x/mod/sumdb/note` (`PRIVATE+KEY+<name>+<key id>+<base64
//! of 0x01 and the seed>`), the format the anchoring library signs
//! checkpoints with ([`LogSigner`]). Its name is the log's origin,
//! `pragmatic/<server name>/<log id>`, fixed when `keygen` makes the first
//! key and never changed by a rotation: witnesses keep their state per
//! origin line, so a log that changed its origin would look like a new log
//! to every witness.
//!
//! A key id is the 4-byte note key id, `SHA-256(name ‖ 0x0A ‖ 0x01 ‖ public
//! key)[:4]`, as in checkpoint signature lines and bundle signatures. Four
//! bytes only hint at a key, so every place that names a key id also
//! carries the full public key, and keys are compared by public key.
//!
//! The core crate only verifies Ed25519; signing goes through the anchoring
//! library's audited implementation, and the tests check signatures with
//! the core verifier.
//!
//! # The key ring
//!
//! `<data_dir>/keys.json` lists every log key the server has signed with
//! and its validity window. `keygen --rotate` closes the old key's window,
//! opens the new one's, and writes a `key.rotate` record signed by both
//! keys ([`KeyRotation`]) to the access log.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use pragmatic::encoding::{hex_decode_exact, hex_encode};
use pragmatic::note::{self, SignatureType};
use pragmatic_anchor::{Cosigner, KeyRotation, LogSigner};
use serde::{Deserialize, Serialize};

use crate::fsutil;
use crate::timefmt;

/// Why a key file could not be used.
#[derive(Debug)]
pub enum KeyError {
    Io(PathBuf, io::Error),
    Format(PathBuf, String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Io(p, e) => write!(f, "key file {}: {e}", p.display()),
            KeyError::Format(p, why) => write!(f, "key file {}: {why}", p.display()),
        }
    }
}

impl std::error::Error for KeyError {}

/// The server's log key (see the module documentation).
pub struct ServerKey {
    signer: LogSigner,
}

impl fmt::Debug for ServerKey {
    /// The origin and key id only, never key material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerKey")
            .field("origin", &self.origin())
            .field("key_id", &self.key_id())
            .finish()
    }
}

impl Clone for ServerKey {
    fn clone(&self) -> ServerKey {
        ServerKey {
            signer: self.log_signer(),
        }
    }
}

/// The hex note key id of a log key under `origin`.
pub fn key_id(origin: &str, public_key: &[u8; 32]) -> String {
    hex_encode(&note::key_id(origin, SignatureType::Ed25519, public_key))
}

impl ServerKey {
    /// The first key of a new log for `server_name`, from the operating
    /// system's CSPRNG. Its origin is `pragmatic/<server_name>/<log id>`.
    pub fn generate(server_name: &str) -> Result<ServerKey, String> {
        LogSigner::generate_log(server_name)
            .map(|signer| ServerKey { signer })
            .map_err(|e| e.to_string())
    }

    /// A fresh key for an existing log's `origin` (a rotation).
    pub fn generate_for_origin(origin: &str) -> Result<ServerKey, String> {
        LogSigner::generate(origin)
            .map(|signer| ServerKey { signer })
            .map_err(|e| e.to_string())
    }

    /// The first key of a new log from a given seed (tests and fixtures).
    pub fn from_seed(server_name: &str, seed: [u8; 32]) -> Result<ServerKey, String> {
        LogSigner::new_log_from_seed(server_name, seed)
            .map(|signer| ServerKey { signer })
            .map_err(|e| e.to_string())
    }

    /// Read a key file.
    pub fn load(path: &Path) -> Result<ServerKey, KeyError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| KeyError::Io(path.to_path_buf(), e))?;
        ServerKey::parse(&text).map_err(|why| KeyError::Format(path.to_path_buf(), why))
    }

    /// Parse a key file's text (Go `note` private key format, type 0x01).
    pub fn parse(text: &str) -> Result<ServerKey, String> {
        if text.contains("-----BEGIN") {
            return Err("a PEM key is not a log key: log keys are signed-note keys \
                 (PRIVATE+KEY+<origin>+...); create one with `pragmatic-server keygen`"
                .into());
        }
        LogSigner::parse_skey(text.trim())
            .map(|signer| ServerKey { signer })
            .map_err(|e| e.to_string())
    }

    /// The key file contents. A secret.
    pub fn encode(&self) -> String {
        format!("{}\n", self.signer.encode_skey())
    }

    /// Write the key to a new file, readable only by its owner. Refuses to
    /// overwrite an existing file.
    pub fn write_new(&self, path: &Path) -> io::Result<()> {
        write_secret(path, self.encode().as_bytes())
    }

    /// The log's origin (the key name).
    pub fn origin(&self) -> &str {
        self.signer.origin()
    }

    /// The server name the origin was made for: its middle component.
    pub fn server_name(&self) -> Option<&str> {
        let rest = self.origin().strip_prefix("pragmatic/")?;
        rest.rsplit_once('/').map(|(name, _)| name)
    }

    /// The 32-byte public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.signer.public_key()
    }

    /// The 4-byte note key id.
    pub fn key_id_bytes(&self) -> [u8; 4] {
        self.signer.key_id()
    }

    /// The note key id as hex.
    pub fn key_id(&self) -> String {
        hex_encode(&self.signer.key_id())
    }

    /// The vkey auditors pin with `--log-key` and witnesses configure.
    pub fn vkey(&self) -> String {
        self.signer.verifier_key().encode()
    }

    /// Sign `message` (Ed25519, RFC 8032).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signer.sign(message)
    }

    /// A second handle on the same key, for the anchoring library, which
    /// owns its signer.
    pub fn log_signer(&self) -> LogSigner {
        LogSigner::parse_skey(&self.signer.encode_skey()).expect("a key it encoded itself")
    }
}

/// Check an Ed25519 signature with the core verifier.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    pragmatic::ed25519::verify(public_key, message, signature)
}

/// Write a secret to a new file, readable only by its owner, creating its
/// directory. Refuses to overwrite an existing file.
pub fn write_secret(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fsutil::create_dir_durable(dir)?;
        }
    }
    fsutil::write_new_private(path, bytes)
}

/// Read the witness-mode cosigner key (`[witness_mode] key_file`): a Go
/// `note` private key of type 0x04, named for the witness.
pub fn load_cosigner(path: &Path) -> Result<Cosigner, KeyError> {
    let text = std::fs::read_to_string(path).map_err(|e| KeyError::Io(path.to_path_buf(), e))?;
    Cosigner::parse_skey(text.trim())
        .map_err(|e| KeyError::Format(path.to_path_buf(), e.to_string()))
}

/// Read the anchor key (`[keys] anchor_key_file`): 32 bytes, as raw bytes
/// or as 64 hex digits (with an optional newline, as `openssl rand -hex
/// 32` writes it).
pub fn load_anchor_key(path: &Path) -> Result<[u8; 32], KeyError> {
    let bytes = std::fs::read(path).map_err(|e| KeyError::Io(path.to_path_buf(), e))?;
    if let Ok(raw) = <[u8; 32]>::try_from(bytes.as_slice()) {
        return Ok(raw);
    }
    let text = std::str::from_utf8(&bytes)
        .unwrap_or("")
        .trim_end_matches(['\n', '\r']);
    hex_decode_exact::<32>(&text.to_ascii_lowercase()).map_err(|_| {
        KeyError::Format(
            path.to_path_buf(),
            "an anchor key is 32 random bytes, raw or as 64 hex digits".into(),
        )
    })
}

/// One key in the key ring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    /// The 4-byte note key id, hex.
    pub key_id: String,
    /// Lowercase hex of the 32-byte public key.
    pub public_key: String,
    pub not_before: String,
    pub not_after: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRingFile {
    keys: Vec<KeyEntry>,
}

/// `<data_dir>/keys.json`.
pub fn key_ring_path(data_dir: &Path) -> PathBuf {
    data_dir.join("keys.json")
}

/// Every key in the ring, oldest first.
pub fn read_key_ring(data_dir: &Path) -> io::Result<Vec<KeyEntry>> {
    Ok(fsutil::read_json::<KeyRingFile>(&key_ring_path(data_dir))?
        .unwrap_or_default()
        .keys)
}

fn write_key_ring(data_dir: &Path, keys: Vec<KeyEntry>) -> io::Result<()> {
    fsutil::write_json_atomic(&key_ring_path(data_dir), &KeyRingFile { keys })
}

fn entry_for(key: &ServerKey, not_before: String) -> KeyEntry {
    KeyEntry {
        key_id: key.key_id(),
        public_key: hex_encode(&key.public_key()),
        not_before,
        not_after: None,
    }
}

/// Make sure the ring lists `key` as current. A key the ring has never seen
/// is added with `not_before` now. A key whose window was closed by a
/// rotation is refused: the server must not sign with a retired key.
pub fn ensure_current(data_dir: &Path, key: &ServerKey) -> io::Result<Vec<KeyEntry>> {
    let mut keys = read_key_ring(data_dir)?;
    let public = hex_encode(&key.public_key());
    match keys.iter().find(|k| k.public_key == public) {
        Some(k) if k.not_after.is_some() => {
            return Err(io::Error::other(format!(
                "signing key {} was retired by a rotation; configure the current key",
                k.key_id
            )))
        }
        Some(_) => {}
        None => {
            keys.push(entry_for(key, timefmt::now_rfc3339()));
            write_key_ring(data_dir, keys.clone())?;
        }
    }
    Ok(keys)
}

/// Close `old`'s window and open `new`'s in the ring. Returns the
/// `key.rotate` record for the access log: the anchoring library's
/// [`KeyRotation`], which both keys sign and which binds both key ids to
/// the origin, plus the origin itself. Refuses keys of different origins:
/// a rotation never changes the origin.
pub fn rotate(
    data_dir: &Path,
    old: &ServerKey,
    new: &ServerKey,
) -> Result<serde_json::Value, String> {
    if old.origin() != new.origin() {
        return Err(format!(
            "a rotation keeps the origin: the old key is for {} and the new one for {}",
            old.origin(),
            new.origin()
        ));
    }
    let at = timefmt::now_unix_secs().max(0) as u64;
    let rotation = KeyRotation::sign(&old.signer, &new.signer, at);
    let at_text = timefmt::rfc3339(at as i64);
    let mut keys = read_key_ring(data_dir).map_err(|e| e.to_string())?;
    let old_public = hex_encode(&old.public_key());
    if !keys.iter().any(|k| k.public_key == old_public) {
        keys.push(entry_for(old, at_text.clone()));
    }
    for k in &mut keys {
        if k.public_key == old_public && k.not_after.is_none() {
            k.not_after = Some(at_text.clone());
        }
    }
    keys.push(entry_for(new, at_text));
    write_key_ring(data_dir, keys).map_err(|e| e.to_string())?;
    let mut record: serde_json::Value =
        serde_json::from_str(&rotation.to_json().to_string()).map_err(|e| e.to_string())?;
    record["origin"] = old.origin().into();
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::testdir::TestDir;

    #[test]
    fn signatures_verify_with_the_core_verifier() {
        let key = ServerKey::generate("test.example").unwrap();
        let sig = key.sign(b"checkpoint body");
        assert!(verify(&key.public_key(), b"checkpoint body", &sig));
        assert!(!verify(&key.public_key(), b"checkpoint bodY", &sig));
    }

    #[test]
    fn the_origin_carries_the_server_name_and_a_log_id() {
        let key = ServerKey::from_seed("prod", [7; 32]).unwrap();
        let origin = key.origin().to_string();
        let log_id = origin.strip_prefix("pragmatic/prod/").unwrap();
        assert_eq!(log_id.len(), 16);
        assert!(log_id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(key.server_name(), Some("prod"));
        assert_eq!(key.key_id(), key_id(&origin, &key.public_key()));
        assert_eq!(key.key_id().len(), 8);
        assert!(key
            .vkey()
            .starts_with(&format!("{origin}+{}+", key.key_id())));
        // A rotation keeps the origin.
        let next = ServerKey::generate_for_origin(&origin).unwrap();
        assert_eq!(next.origin(), origin);
        assert_ne!(next.public_key(), key.public_key());
    }

    #[test]
    fn key_files_round_trip_and_are_never_overwritten() {
        let d = TestDir::new("keyfile");
        let p = d.join("etc/server.key");
        let key = ServerKey::generate("test.example").unwrap();
        key.write_new(&p).unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.starts_with("PRIVATE+KEY+pragmatic/test.example/"));
        let back = ServerKey::load(&p).unwrap();
        assert_eq!(back.public_key(), key.public_key());
        assert_eq!(back.origin(), key.origin());
        assert!(ServerKey::generate("x").unwrap().write_new(&p).is_err());
        let secret = text.trim().rsplit('+').next().unwrap();
        assert!(!format!("{key:?}").contains(secret));
        // The PEM keys of earlier development builds are refused with a
        // pointer to keygen.
        let pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        assert!(ServerKey::parse(pem).unwrap_err().contains("keygen"));
    }

    #[test]
    fn rotation_closes_the_old_window_and_signs_with_both() {
        let d = TestDir::new("keys");
        let old = ServerKey::generate("test.example").unwrap();
        let new = ServerKey::generate_for_origin(old.origin()).unwrap();
        ensure_current(&d, &old).unwrap();
        ensure_current(&d, &old).unwrap();
        assert_eq!(read_key_ring(&d).unwrap().len(), 1);
        let record = rotate(&d, &old, &new).unwrap();
        let ring = read_key_ring(&d).unwrap();
        assert_eq!(ring.len(), 2);
        assert!(ring[0].not_after.is_some());
        assert!(ring[1].not_after.is_none());
        assert_eq!(record["old_key_id"], old.key_id());
        assert_eq!(record["new_key_id"], new.key_id());
        assert_eq!(record["origin"], old.origin());
        let mut fields = record.clone();
        fields.as_object_mut().unwrap().remove("origin");
        let doc = pragmatic::json::Json::parse(&fields.to_string()).unwrap();
        let rotation = KeyRotation::from_json(&doc).unwrap();
        assert!(rotation.verify(old.origin()));
        assert!(ensure_current(&d, &old).is_err());
        ensure_current(&d, &new).unwrap();
        // Another origin is never a rotation.
        let stranger = ServerKey::generate("elsewhere").unwrap();
        assert!(rotate(&d, &new, &stranger).is_err());
    }

    #[test]
    fn anchor_keys_are_raw_or_hex() {
        let d = TestDir::new("anchor-key");
        let raw = d.join("raw");
        std::fs::write(&raw, [9u8; 32]).unwrap();
        assert_eq!(load_anchor_key(&raw).unwrap(), [9u8; 32]);
        let hex = d.join("hex");
        std::fs::write(&hex, format!("{}\n", hex_encode(&[10u8; 32]))).unwrap();
        assert_eq!(load_anchor_key(&hex).unwrap(), [10u8; 32]);
        let short = d.join("short");
        std::fs::write(&short, b"too short").unwrap();
        assert!(load_anchor_key(&short).is_err());
    }
}
