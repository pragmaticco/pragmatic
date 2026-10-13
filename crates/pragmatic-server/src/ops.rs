//! Operations on a data directory: backup, restore, verify-data, migrate
//! and key generation (design 4.1, 4.7 and 4.13).
//!
//! # Backup
//!
//! `backup --to DIR` works on a live data directory, without stopping the
//! server. Each journal is opened first and its `meta.json` read after, and
//! the copy stops at the indexed length (`meta.byte_len`), or at the last
//! whole frame before it if an erasure replaced the file in between (the
//! open file keeps the old contents, so the copy is always a valid
//! prefix). Then come the tombstones, anchors, the access log, tokens,
//! holds, keys, the subjects index key, `FORMAT` and the erasure ledger.
//! `manifest.json` lists every file with its SHA-256 and is signed with
//! the server's key.
//!
//! # Restore
//!
//! `restore --from DIR [--erasure-ledger FILE]` needs the server stopped
//! and an empty data directory. It checks the manifest's signature and
//! every file's hash, copies the files, and then re-applies every ledger
//! record newer than the backup: erasures and shreds are erased again,
//! deletions deleted again. Without that, restoring a backup taken before
//! an erasure would bring erased personal data back; the ledger given
//! here should be the copy streamed off the host. Runs with fewer entries
//! than were anchored (by the backup's own records, the ledger or the
//! anchor log) are marked `regressed`. The restore is recorded in the
//! access log.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use pragmatic::encoding::{hex_decode_exact, hex_encode};
use pragmatic::journal::{ErasureNote, HEADER_LEN};
use pragmatic::sha256::sha256;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};

use crate::access_log::{self, AccessLog, AccessRecord};
use crate::config::Config;
use crate::hooks::Anchoring;
use crate::keys::{self, ServerKey};
use crate::layout::{self, Layout};
use crate::ledger::{self, Ledger, LedgerKind};
use crate::metrics::Metrics;
use crate::server::lock_data_dir;
use crate::store::{AnchorSoon, Meta, Signals, Store, StoreOptions};
use crate::webhooks::Webhooks;
use crate::{fsutil, timefmt};

/// The manifest format.
pub const MANIFEST_FORMAT: &str = "pragmatic-backup/1";

/// One copied file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

/// One copied run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestRun {
    pub run_id: String,
    pub byte_len: u64,
}

/// The signature over a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSignature {
    pub key_id: String,
    pub public_key: String,
    /// Ed25519 over SHA-256 of the canonical manifest without this field.
    pub value: String,
}

/// `manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: String,
    pub created_at: String,
    pub server_version: String,
    pub data_format: u32,
    /// The last erasure ledger record in the backup.
    pub ledger_seq: u64,
    pub runs: Vec<ManifestRun>,
    pub files: Vec<ManifestFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ManifestSignature>,
}

/// The bytes a manifest's signature covers: SHA-256 of its canonical JSON
/// (keys sorted, no whitespace) without the signature.
fn signed_digest(m: &Manifest) -> Result<[u8; 32], String> {
    let mut unsigned = m.clone();
    unsigned.signature = None;
    let text = serde_json::to_string(&unsigned).map_err(|e| e.to_string())?;
    let doc = pragmatic::json::parse(&text).map_err(|e| e.to_string())?;
    Ok(sha256(doc.canonical_string().as_bytes()))
}

/// What a backup did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupReport {
    pub runs: u64,
    pub files: u64,
    pub bytes: u64,
    pub manifest: PathBuf,
}

/// The largest whole-frame prefix of a journal file not longer than
/// `limit`, found by reading only the frames' length prefixes.
fn frame_prefix(file: &fs::File, limit: u64) -> io::Result<u64> {
    let limit = limit.min(file.metadata()?.len());
    let header = HEADER_LEN as u64;
    if limit < header {
        return Ok(0);
    }
    let mut pos = header;
    let mut len = [0u8; 4];
    while pos + 4 <= limit {
        fsutil::read_exact_at(file, &mut len, pos)?;
        let end = pos + 4 + u64::from(u32::from_le_bytes(len)) + 32;
        if end > limit {
            break;
        }
        pos = end;
    }
    Ok(pos)
}

struct Copier<'a> {
    from: &'a Path,
    to: &'a Path,
    files: Vec<ManifestFile>,
    bytes: u64,
}

impl Copier<'_> {
    /// Write `bytes` at `rel` in the backup and list it.
    fn put(&mut self, rel: &str, bytes: &[u8]) -> io::Result<()> {
        let dest = self.to.join(rel);
        if let Some(dir) = dest.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&dest, bytes)?;
        fs::File::open(&dest)?.sync_all()?;
        self.files.push(ManifestFile {
            path: rel.to_string(),
            bytes: bytes.len() as u64,
            sha256: hex_encode(&sha256(bytes)),
        });
        self.bytes += bytes.len() as u64;
        Ok(())
    }

    /// Copy the first `len` bytes of an open file to `rel`, hashing as it
    /// goes, without holding the file in memory.
    fn put_prefix(&mut self, rel: &str, file: &fs::File, len: u64) -> io::Result<()> {
        use std::io::Write;
        let dest = self.to.join(rel);
        if let Some(dir) = dest.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut out = io::BufWriter::new(fs::File::create(&dest)?);
        let mut hash = pragmatic::sha256::Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut offset = 0u64;
        while offset < len {
            let n = (len - offset).min(buf.len() as u64) as usize;
            fsutil::read_exact_at(file, &mut buf[..n], offset)?;
            hash.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            offset += n as u64;
        }
        out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        self.files.push(ManifestFile {
            path: rel.to_string(),
            bytes: len,
            sha256: hex_encode(&hash.finalize()),
        });
        self.bytes += len;
        Ok(())
    }

    /// Copy a file if it exists.
    fn copy(&mut self, rel: &str) -> io::Result<()> {
        match fs::read(self.from.join(rel)) {
            Ok(b) => self.put(rel, &b),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Copy a directory tree (the anchoring library's files).
    fn copy_tree(&mut self, rel: &str) -> io::Result<()> {
        let dir = self.from.join(rel);
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        for e in entries {
            let e = e?;
            let name = format!("{rel}/{}", e.file_name().to_string_lossy());
            if e.file_type()?.is_dir() {
                self.copy_tree(&name)?;
            } else {
                self.copy(&name)?;
            }
        }
        Ok(())
    }
}

/// `backup --to DIR` (see the module documentation).
pub fn backup(config: &Config, to: &Path) -> Result<BackupReport, String> {
    let key = ServerKey::load(&config.keys.signing_key_file).map_err(|e| e.to_string())?;
    if !layout::is_fresh(to).map_err(|e| e.to_string())? {
        return Err(format!("{} is not empty", to.display()));
    }
    fs::create_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
    let from = config.data_dir.as_path();
    let layout = Layout::new(from);
    let mut c = Copier {
        from,
        to,
        files: Vec::new(),
        bytes: 0,
    };
    let runs = copy_runs(&layout, &mut c).map_err(|e| format!("runs: {e}"))?;
    let io = |e: io::Error| e.to_string();
    c.copy_tree("anchors").map_err(io)?;
    copy_access_log(&mut c).map_err(io)?;
    for f in [
        "tokens.json",
        "holds.json",
        "keys.json",
        "index.key",
        "FORMAT",
    ] {
        c.copy(f).map_err(io)?;
    }
    let ledger_seq = copy_ledger(&mut c).map_err(io)?;
    let mut manifest = Manifest {
        format: MANIFEST_FORMAT.into(),
        created_at: timefmt::now_rfc3339(),
        server_version: env!("CARGO_PKG_VERSION").into(),
        data_format: layout::DATA_FORMAT,
        ledger_seq,
        runs,
        files: c.files,
        signature: None,
    };
    let digest = signed_digest(&manifest)?;
    manifest.signature = Some(ManifestSignature {
        key_id: key.key_id(),
        public_key: hex_encode(&key.public_key()),
        value: hex_encode(&key.sign(&digest)),
    });
    let path = to.join("manifest.json");
    fsutil::write_json_atomic(&path, &manifest).map_err(io)?;
    Ok(BackupReport {
        runs: manifest.runs.len() as u64,
        files: manifest.files.len() as u64,
        bytes: c.bytes,
        manifest: path,
    })
}

/// Every run's journal (to its indexed length), meta and tombstone.
fn copy_runs(layout: &Layout, c: &mut Copier<'_>) -> io::Result<Vec<ManifestRun>> {
    let mut runs = Vec::new();
    let shards = match fs::read_dir(layout.runs_dir()) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(runs),
        Err(e) => return Err(e),
    };
    for shard in shards {
        let shard = shard?;
        let hh = shard.file_name().to_string_lossy().into_owned();
        for e in fs::read_dir(shard.path())? {
            let name = e?.file_name().to_string_lossy().into_owned();
            if let Some(stem) = name.strip_suffix(".tombstone.json") {
                c.copy(&format!("runs/{hh}/{stem}.tombstone.json"))?;
            }
            let Some(stem) = name.strip_suffix(".meta.json") else {
                continue;
            };
            // Journal first (by descriptor), then meta: see the module docs.
            let journal = match fs::File::open(layout.journal(stem)) {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            let meta_bytes = fs::read(layout.meta(stem))?;
            let meta: Meta = serde_json::from_slice(&meta_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            let cut = frame_prefix(&journal, meta.byte_len)?;
            c.put_prefix(&format!("runs/{hh}/{stem}.journal"), &journal, cut)?;
            c.put(&format!("runs/{hh}/{stem}.meta.json"), &meta_bytes)?;
            runs.push(ManifestRun {
                run_id: meta.run_id,
                byte_len: cut,
            });
        }
    }
    runs.sort_by(|a, b| a.run_id.cmp(&b.run_id));
    Ok(runs)
}

/// The access log, to its last whole frame.
fn copy_access_log(c: &mut Copier<'_>) -> io::Result<()> {
    let rel = "audit/access.journal";
    match fs::File::open(c.from.join(rel)) {
        Ok(file) => {
            let cut = frame_prefix(&file, u64::MAX)?;
            c.put_prefix(rel, &file, cut)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// The erasure ledger's complete lines. Returns the last record's seq.
fn copy_ledger(c: &mut Copier<'_>) -> io::Result<u64> {
    let rel = "erasure-ledger.jsonl";
    let bytes = match fs::read(c.from.join(rel)) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let cut = bytes.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    c.put(rel, &bytes[..cut])?;
    let records = ledger::read(&c.to.join(rel))?;
    Ok(records.last().map_or(0, |r| r.seq))
}

/// Read a backup's manifest and check its signature, its key and every
/// file's hash.
pub fn verify_backup(dir: &Path) -> Result<Manifest, String> {
    let m: Manifest = fsutil::read_json(&dir.join("manifest.json"))
        .map_err(|e| format!("manifest.json: {e}"))?
        .ok_or("manifest.json is missing")?;
    if m.format != MANIFEST_FORMAT {
        return Err(format!("unknown backup format '{}'", m.format));
    }
    let sig = m.signature.clone().ok_or("the manifest is not signed")?;
    let public: [u8; 32] =
        hex_decode_exact(&sig.public_key).map_err(|_| "bad manifest public key")?;
    let value: [u8; 64] = hex_decode_exact(&sig.value).map_err(|_| "bad manifest signature")?;
    if keys::key_id(&public) != sig.key_id || !keys::verify(&public, &signed_digest(&m)?, &value) {
        return Err("the manifest signature does not verify".into());
    }
    let ring = keys::read_key_ring(dir).map_err(|e| format!("keys.json: {e}"))?;
    if !ring.iter().any(|k| k.key_id == sig.key_id) {
        return Err("the manifest was signed by a key that is not in the backup's key ring".into());
    }
    for f in &m.files {
        if f.path.contains("..") || f.path.starts_with('/') {
            return Err(format!("unsafe path in the manifest: {}", f.path));
        }
        let bytes = fs::read(dir.join(&f.path)).map_err(|e| format!("{}: {e}", f.path))?;
        if hex_encode(&sha256(&bytes)) != f.sha256 {
            return Err(format!("{} does not match the manifest", f.path));
        }
    }
    Ok(m)
}

/// A store over a data directory for offline work (no webhooks).
fn offline_store(config: &Config, layout: &Layout) -> Result<Arc<Store>, String> {
    let index_key = layout::index_key(layout).map_err(|e| format!("index.key: {e}"))?;
    let store = Store::new(
        layout.clone(),
        StoreOptions {
            lease_ttl: Duration::from_secs(config.lease_ttl_secs),
            max_clock_skew: Duration::from_secs(config.max_clock_skew_secs),
            index_key,
        },
        Signals {
            metrics: Arc::new(Metrics::default()),
            webhooks: Webhooks::disabled(),
            anchor_soon: Arc::new(AnchorSoon::default()),
        },
    );
    let report = store.index();
    if let Some(e) = report.errors.first() {
        return Err(format!("index: {e}"));
    }
    Ok(Arc::new(store))
}

/// `restore --from DIR [--erasure-ledger FILE]` (see the module
/// documentation). Returns a report.
pub fn restore(
    config: &Config,
    from: &Path,
    ledger_file: Option<&Path>,
    anchoring: &dyn Anchoring,
) -> Result<JsonValue, String> {
    let manifest = verify_backup(from)?;
    let layout = Layout::new(config.data_dir.clone());
    let _lock = lock_data_dir(&layout).map_err(|e| e.0)?;
    if !layout::is_fresh(&layout.data_dir).map_err(|e| e.to_string())? {
        return Err(format!(
            "{} is not empty; restore into an empty data directory",
            layout.data_dir.display()
        ));
    }
    for f in &manifest.files {
        let dest = layout.data_dir.join(&f.path);
        if let Some(dir) = dest.parent() {
            fsutil::create_dir_durable(dir).map_err(|e| e.to_string())?;
        }
        let bytes = fs::read(from.join(&f.path)).map_err(|e| format!("{}: {e}", f.path))?;
        fsutil::write_atomic(&dest, &bytes).map_err(|e| format!("{}: {e}", f.path))?;
    }
    layout::check_format(&layout)?;
    let access = AccessLog::open(&access_log::path(&layout.data_dir)).map_err(|e| e.to_string())?;
    let begin = access
        .durable_blocking(AccessRecord::new(
            "restore",
            json!({"phase": "begin", "manifest_created_at": manifest.created_at, "ledger_seq": manifest.ledger_seq}),
        ))
        .map_err(|e| e.0)?;
    let store = offline_store(config, &layout)?;
    store.clear_leases();
    let records = match ledger_file {
        Some(f) => ledger::read(f).map_err(|e| format!("{}: {e}", f.display()))?,
        None => ledger::read(&Ledger::path(&layout.data_dir)).map_err(|e| e.to_string())?,
    };
    let restored_ledger = Ledger::open(&layout.data_dir).map_err(|e| e.to_string())?;
    let mut anchored = anchoring.anchored_lengths().map_err(|e| e.0)?;
    let (mut applied, mut slots, mut deleted, mut errors) = (0u64, 0u64, Vec::new(), Vec::new());
    for r in records.iter().filter(|r| r.seq > manifest.ledger_seq) {
        let a = anchored.entry(r.run_id.clone()).or_insert(0);
        *a = (*a).max(r.anchored_entries);
        let note = ErasureNote {
            by: r.by.clone(),
            authenticated: true,
            reason_code: r.reason_code.clone(),
            access_log_cursor: Some(begin),
            reason: format!("re-applied from erasure ledger record {} by restore", r.seq),
        };
        let outcome = match r.kind {
            LedgerKind::Erasure => store
                .reapply_erasure(&r.run_id, Some(&r.slots), &note)
                .map(|(s, _)| s.len()),
            LedgerKind::Shred => store
                .reapply_erasure(&r.run_id, None, &note)
                .map(|(s, _)| s.len()),
            LedgerKind::Delete => store.reapply_delete(&r.run_id, &r.at).map(|_| {
                deleted.push(r.run_id.clone());
                0
            }),
        };
        match outcome {
            Ok(n) => slots += n as u64,
            Err(e) if e.code == "not_found" || e.code == "run_deleted" => {}
            Err(e) => errors.push(json!({"seq": r.seq, "run_id": r.run_id, "error": e.message})),
        }
        let mut copy = r.clone();
        copy.access_log_cursor = Some(begin);
        restored_ledger
            .append(copy)
            .map_err(|e| format!("erasure ledger: {e}"))?;
        applied += 1;
    }
    let regressed = store.apply_anchored_lengths(&anchored);
    store.flush_meta(true);
    let report = json!({
        "phase": "done",
        "from": from.display().to_string(),
        "manifest_created_at": manifest.created_at,
        "runs": manifest.runs.len(),
        "ledger_records_applied": applied,
        "slots_erased_again": slots,
        "runs_deleted_again": deleted,
        "regressed": regressed,
        "errors": errors,
    });
    access
        .durable_blocking(AccessRecord::new("restore", report.clone()))
        .map_err(|e| e.0)?;
    Ok(report)
}

/// `verify-data --offline`: verify a stopped server's data and record the
/// result in its access log.
pub fn verify_data_offline(
    config: &Config,
    anchoring: &dyn Anchoring,
) -> Result<JsonValue, String> {
    let layout = Layout::new(config.data_dir.clone());
    let _lock = lock_data_dir(&layout).map_err(|e| e.0)?;
    layout::check_format(&layout)?;
    let store = offline_store(config, &layout)?;
    let (checked, failing) = store.verify_all();
    let failing_ids: Vec<String> = store
        .all()
        .iter()
        .filter(|r| r.lock().broken.is_some())
        .map(|r| r.id.clone())
        .collect();
    let log_path = access_log::path(&layout.data_dir);
    let access_ok = match fs::read(&log_path) {
        Ok(b) => pragmatic::Journal::audit_bytes(&b, None).is_ok_and(|(_, r)| r.is_ok()),
        Err(_) => false,
    };
    let anchors = anchoring.verify().unwrap_or_else(|e| json!({"error": e.0}));
    let result = json!({
        "runs_checked": checked,
        "runs_failing": failing,
        "failing_run_ids": failing_ids,
        "access_log": {"ok": access_ok},
        "anchors": anchors,
        "at": timefmt::now_rfc3339(),
        "offline": true,
    });
    let access = AccessLog::open(&log_path).map_err(|e| e.to_string())?;
    access
        .durable_blocking(AccessRecord::new("verify-data", result.clone()))
        .map_err(|e| e.0)?;
    Ok(result)
}

/// `migrate`: bring the data directory to this build's data format.
pub fn migrate(config: &Config) -> Result<String, String> {
    let layout = Layout::new(config.data_dir.clone());
    let _lock = lock_data_dir(&layout).map_err(|e| e.0)?;
    match layout::read_format(&layout).map_err(|e| e.to_string())? {
        Some(v) if v == layout::DATA_FORMAT => {
            Ok(format!("data format {v} is current; nothing to do"))
        }
        Some(v) if v > layout::DATA_FORMAT => Err(format!(
            "data format {v} is newer than this build ({}); use a newer server",
            layout::DATA_FORMAT
        )),
        Some(v) => Err(format!("no migration from data format {v}")),
        None => {
            // Data written before FORMAT existed (development builds of
            // 0.6): check that every meta reads, then record format 1.
            let store = offline_store(config, &layout)?;
            let n = store.len();
            layout::write_format(&layout, layout::DATA_FORMAT).map_err(|e| e.to_string())?;
            Ok(format!(
                "recorded data format {} ({n} runs checked)",
                layout::DATA_FORMAT
            ))
        }
    }
}

/// `keygen`: write a new signing key. With `rotate`, replace the current
/// key: the old key's window closes, a `key.rotate` record signed by both
/// keys goes into the access log, the old key file is kept beside the new
/// one with a `.retired-<unix>` suffix. Rotation needs the server stopped.
pub fn keygen(config: &Config, rotate: bool) -> Result<String, String> {
    let path = config.keys.signing_key_file.as_path();
    let new = ServerKey::generate().map_err(|e| e.to_string())?;
    if !rotate {
        if path.exists() {
            return Err(format!(
                "{} exists; use --rotate to replace it",
                path.display()
            ));
        }
        new.write_new(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        return Ok(describe(&new, path));
    }
    let old = ServerKey::load(path).map_err(|e| e.to_string())?;
    let layout = Layout::new(config.data_dir.clone());
    let _lock = lock_data_dir(&layout).map_err(|e| e.0)?;
    let staged = path.with_extension(format!("new-{}", timefmt::now_unix_secs()));
    new.write_new(&staged)
        .map_err(|e| format!("{}: {e}", staged.display()))?;
    let record = keys::rotate(&layout.data_dir, &old, &new).map_err(|e| e.to_string())?;
    let access = AccessLog::open(&access_log::path(&layout.data_dir)).map_err(|e| e.to_string())?;
    access
        .durable_blocking(AccessRecord::new("key.rotate", record))
        .map_err(|e| e.0)?;
    let retired = path.with_extension(format!("retired-{}", timefmt::now_unix_secs()));
    fs::rename(path, &retired).map_err(|e| e.to_string())?;
    fs::rename(&staged, path).map_err(|e| e.to_string())?;
    if let Some(dir) = path.parent() {
        let _ = fsutil::fsync_dir(dir);
    }
    Ok(format!(
        "{}old key kept at {}\n",
        describe(&new, path),
        retired.display()
    ))
}

fn describe(key: &ServerKey, path: &Path) -> String {
    format!(
        "wrote {}\nkey_id {}\npublic_key {}\n",
        path.display(),
        key.key_id(),
        hex_encode(&key.public_key())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_prefixes_stop_at_whole_frames() {
        let mut j = pragmatic::Journal::new(None);
        for i in 0..3 {
            j.append(
                pragmatic::journal::META,
                pragmatic::Event::Note {
                    kind: "x".into(),
                    data: format!("{{\"i\":{i}}}"),
                    payload: vec![],
                },
            )
            .unwrap();
        }
        j.mark_persisted(j.len());
        let bytes = j.to_bytes();
        let d = crate::fsutil::testdir::TestDir::new("prefix");
        let path = d.join("j");
        fs::write(&path, &bytes).unwrap();
        let f = fs::File::open(&path).unwrap();
        assert_eq!(frame_prefix(&f, u64::MAX).unwrap(), bytes.len() as u64);
        let one = (HEADER_LEN + j.frame_bytes(0).unwrap().len()) as u64;
        assert_eq!(frame_prefix(&f, one + 5).unwrap(), one);
        assert_eq!(frame_prefix(&f, 3).unwrap(), 0);
    }
}
