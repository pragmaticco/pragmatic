//! The server's Ed25519 signing key, its key file and the key ring
//! (design 4.1, 4.7 and 4.13).
//!
//! The server signs anchoring checkpoints, backup manifests and key
//! rotations. The core crate only *verifies* Ed25519 (it has no
//! dependencies); signing uses `ed25519-dalek`, and everything this module
//! signs is checked against the core verifier in its tests, so the two
//! agree on every byte.
//!
//! # Key file
//!
//! A PKCS#8 PEM `PRIVATE KEY` holding an Ed25519 seed (RFC 8410), the form
//! `openssl genpkey -algorithm ed25519` writes, so operators can generate,
//! inspect and store keys with tools they already trust. The file is
//! refused inside `data_dir` (see [`crate::config`]).
//!
//! # Key ids and the key ring
//!
//! A key id is the lowercase hex SHA-256 of the 32-byte public key: stable,
//! unambiguous and independent of any name. `<data_dir>/keys.json` lists
//! every key the server has signed with and its validity window, which
//! `GET /v1/keys` serves; `keygen --rotate` closes the old key's window and
//! opens the new one's.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use pragmatic::encoding::{base64_decode, base64_encode, hex_encode};
use pragmatic::sha256::sha256;
use serde::{Deserialize, Serialize};

use crate::fsutil;
use crate::timefmt;

/// The DER prefix of a version 1 PKCS#8 Ed25519 private key; the 32-byte
/// seed follows.
const PKCS8_V1_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// The DER prefix of a version 2 key (with the public key attached).
const PKCS8_V2_PREFIX: [u8; 16] = [
    0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// What follows the seed in a version 2 key: `[1] BIT STRING` of the
/// public key.
const PKCS8_V2_PUBLIC: [u8; 3] = [0x81, 0x21, 0x00];

/// Why a key file could not be used.
#[derive(Debug)]
pub enum KeyError {
    Io(PathBuf, io::Error),
    Format(PathBuf, &'static str),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Io(p, e) => write!(f, "signing key {}: {e}", p.display()),
            KeyError::Format(p, why) => write!(f, "signing key {}: {why}", p.display()),
        }
    }
}

impl std::error::Error for KeyError {}

/// The server's Ed25519 key pair.
#[derive(Clone)]
pub struct ServerKey {
    signing: SigningKey,
    public: [u8; 32],
}

impl fmt::Debug for ServerKey {
    /// The key id only, never the private key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerKey")
            .field("key_id", &self.key_id())
            .finish()
    }
}

/// The key id of a public key: lowercase hex SHA-256.
pub fn key_id(public_key: &[u8; 32]) -> String {
    hex_encode(&sha256(public_key))
}

impl ServerKey {
    /// A key from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> ServerKey {
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        ServerKey { signing, public }
    }

    /// A fresh key from the operating system's CSPRNG.
    pub fn generate() -> io::Result<ServerKey> {
        let mut seed = [0u8; 32];
        pragmatic::rand::fill(&mut seed)?;
        Ok(ServerKey::from_seed(seed))
    }

    /// Read a PKCS#8 PEM key file.
    pub fn load(path: &Path) -> Result<ServerKey, KeyError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| KeyError::Io(path.to_path_buf(), e))?;
        ServerKey::from_pem(&text).map_err(|why| KeyError::Format(path.to_path_buf(), why))
    }

    /// Parse PKCS#8 PEM text.
    pub fn from_pem(text: &str) -> Result<ServerKey, &'static str> {
        let body = text
            .trim()
            .strip_prefix("-----BEGIN PRIVATE KEY-----")
            .and_then(|r| r.strip_suffix("-----END PRIVATE KEY-----"))
            .ok_or("not a PEM PRIVATE KEY")?;
        let b64: String = body.split_whitespace().collect();
        let der = base64_decode(&b64).map_err(|_| "PEM body is not base64")?;
        let v1 = der.len() == 48 && der[..16] == PKCS8_V1_PREFIX;
        let v2 = der.len() == 83 && der[..16] == PKCS8_V2_PREFIX && der[48..51] == PKCS8_V2_PUBLIC;
        if !v1 && !v2 {
            return Err("not a PKCS#8 Ed25519 private key");
        }
        let seed: [u8; 32] = der[16..48].try_into().expect("32 bytes");
        let key = ServerKey::from_seed(seed);
        if der.len() == 83 && der[51..83] != key.public {
            return Err("the attached public key does not match the private key");
        }
        Ok(key)
    }

    /// The key as PKCS#8 PEM text.
    pub fn to_pem(&self) -> String {
        let mut der = PKCS8_V1_PREFIX.to_vec();
        der.extend_from_slice(&self.signing.to_bytes());
        let b64 = base64_encode(&der);
        let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            out.push('\n');
        }
        out.push_str("-----END PRIVATE KEY-----\n");
        out
    }

    /// Write the key to a new file, readable only by its owner. Refuses to
    /// overwrite an existing file.
    pub fn write_new(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                fsutil::create_dir_durable(dir)?;
            }
        }
        fsutil::write_new_private(path, self.to_pem().as_bytes())
    }

    /// The 32-byte public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// The key id (see the module documentation).
    pub fn key_id(&self) -> String {
        key_id(&self.public)
    }

    /// Sign `message` (Ed25519, RFC 8032).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

/// Check an Ed25519 signature with the core verifier.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    pragmatic::ed25519::verify(public_key, message, signature)
}

/// One key in the key ring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
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
    match keys.iter().find(|k| k.key_id == key.key_id()) {
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

/// The message both keys sign in a `key.rotate` record.
pub fn rotation_message(old: &[u8; 32], new: &[u8; 32], at: &str) -> String {
    format!(
        "pragmatic/key.rotate/v1\n{}\n{}\n{at}\n",
        hex_encode(old),
        hex_encode(new)
    )
}

/// Close `old`'s window and open `new`'s in the ring. Returns the
/// `key.rotate` record (old and new key ids, signed by both) for the
/// access log.
pub fn rotate(data_dir: &Path, old: &ServerKey, new: &ServerKey) -> io::Result<serde_json::Value> {
    let at = timefmt::now_rfc3339();
    let mut keys = read_key_ring(data_dir)?;
    if !keys.iter().any(|k| k.key_id == old.key_id()) {
        keys.push(entry_for(old, at.clone()));
    }
    for k in &mut keys {
        if k.key_id == old.key_id() && k.not_after.is_none() {
            k.not_after = Some(at.clone());
        }
    }
    keys.push(entry_for(new, at.clone()));
    write_key_ring(data_dir, keys)?;
    let message = rotation_message(&old.public_key(), &new.public_key(), &at);
    Ok(serde_json::json!({
        "old_key_id": old.key_id(),
        "new_key_id": new.key_id(),
        "old_public_key": hex_encode(&old.public_key()),
        "new_public_key": hex_encode(&new.public_key()),
        "at": at,
        "old_signature": hex_encode(&old.sign(message.as_bytes())),
        "new_signature": hex_encode(&new.sign(message.as_bytes())),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::testdir::TestDir;
    use pragmatic::encoding::hex_decode_exact;

    #[test]
    fn signatures_verify_with_the_core_verifier() {
        let key = ServerKey::generate().unwrap();
        let sig = key.sign(b"checkpoint body");
        assert!(verify(&key.public_key(), b"checkpoint body", &sig));
        assert!(!verify(&key.public_key(), b"checkpoint bodY", &sig));
    }

    #[test]
    fn rfc8032_test_vector_1() {
        let seed = hex_decode_exact::<32>(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )
        .unwrap();
        let key = ServerKey::from_seed(seed);
        assert_eq!(
            hex_encode(&key.public_key()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(
            hex_encode(&key.sign(b"")),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn pem_round_trips_and_matches_openssl_layout() {
        let key = ServerKey::generate().unwrap();
        let pem = key.to_pem();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEI"));
        let back = ServerKey::from_pem(&pem).unwrap();
        assert_eq!(back.public_key(), key.public_key());
        assert!(ServerKey::from_pem(
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"
        )
        .is_err());
        assert!(ServerKey::from_pem("hello").is_err());
        assert!(!format!("{key:?}").contains(&hex_encode(&key.signing.to_bytes())));
    }

    #[test]
    fn rotation_closes_the_old_window_and_signs_with_both() {
        let d = TestDir::new("keys");
        let old = ServerKey::generate().unwrap();
        let new = ServerKey::generate().unwrap();
        ensure_current(&d, &old).unwrap();
        ensure_current(&d, &old).unwrap();
        assert_eq!(read_key_ring(&d).unwrap().len(), 1);
        let record = rotate(&d, &old, &new).unwrap();
        let ring = read_key_ring(&d).unwrap();
        assert_eq!(ring.len(), 2);
        assert!(ring[0].not_after.is_some());
        assert!(ring[1].not_after.is_none());
        let message = rotation_message(
            &old.public_key(),
            &new.public_key(),
            record["at"].as_str().unwrap(),
        );
        for (who, k) in [("old", &old), ("new", &new)] {
            let sig: [u8; 64] =
                hex_decode_exact(record[format!("{who}_signature")].as_str().unwrap()).unwrap();
            assert!(verify(&k.public_key(), message.as_bytes(), &sig));
        }
        assert!(ensure_current(&d, &old).is_err());
        ensure_current(&d, &new).unwrap();
    }

    #[test]
    fn key_files_are_never_overwritten() {
        let d = TestDir::new("keyfile");
        let p = d.join("etc/server.ed25519");
        let key = ServerKey::generate().unwrap();
        key.write_new(&p).unwrap();
        assert_eq!(ServerKey::load(&p).unwrap().key_id(), key.key_id());
        assert!(ServerKey::generate().unwrap().write_new(&p).is_err());
    }
}
