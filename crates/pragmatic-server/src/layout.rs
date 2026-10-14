//! The data directory (design 4.2).
//!
//! ```text
//! <data_dir>/
//!   FORMAT                              {"data_format": 1}
//!   server.lock
//!   tokens.json                         issued tokens (atomic writes)
//!   holds.json                          legal holds (atomic writes)
//!   keys.json                           every signing key and its validity window
//!   index.key                           the subjects index HMAC key (32 bytes)
//!   runs/<hh>/<64hex>.journal           hh = first 2 hex of SHA-256(run_id)
//!   runs/<hh>/<64hex>.meta.json
//!   runs/<hh>/<64hex>.tombstone.json
//!   runs/<hh>/<64hex>.torn-<unix_ms>    torn tails moved aside
//!   anchors/                            the anchoring library's log and checkpoints
//!   audit/access.journal                the access log, journal format 2
//!   erasure-ledger.jsonl                every erasure, shred and delete
//! ```
//!
//! File names are hashes of run ids, so any run id (they may contain `:`
//! and `.`) maps to a safe, fixed-length name, and listing the directory
//! reveals no run ids.

use std::io;
use std::path::{Path, PathBuf};

use pragmatic::encoding::hex_encode;
use pragmatic::sha256::sha256;
use serde::{Deserialize, Serialize};

use crate::fsutil;

/// The data format this build reads and writes.
pub const DATA_FORMAT: u32 = 1;

/// The paths of one data directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub data_dir: PathBuf,
}

/// `hex(SHA-256(run_id))`, the stem of every file of a run.
pub fn stem(run_id: &str) -> String {
    hex_encode(&sha256(run_id.as_bytes()))
}

/// True for a 64-digit lowercase hex stem.
pub fn is_stem(s: &str) -> bool {
    crate::config::is_sha256_hex(s)
}

impl Layout {
    pub fn new(data_dir: impl Into<PathBuf>) -> Layout {
        Layout {
            data_dir: data_dir.into(),
        }
    }

    pub fn runs_dir(&self) -> PathBuf {
        self.data_dir.join("runs")
    }

    /// `runs/<hh>` for a stem.
    pub fn run_dir(&self, stem: &str) -> PathBuf {
        self.runs_dir().join(&stem[..2])
    }

    pub fn journal(&self, stem: &str) -> PathBuf {
        self.run_dir(stem).join(format!("{stem}.journal"))
    }

    pub fn meta(&self, stem: &str) -> PathBuf {
        self.run_dir(stem).join(format!("{stem}.meta.json"))
    }

    pub fn tombstone(&self, stem: &str) -> PathBuf {
        self.run_dir(stem).join(format!("{stem}.tombstone.json"))
    }

    /// Where a torn tail moved aside at `unix_ms` goes.
    pub fn torn(&self, stem: &str, unix_ms: u64) -> PathBuf {
        self.run_dir(stem).join(format!("{stem}.torn-{unix_ms}"))
    }

    /// Every moved-aside torn tail of a run.
    pub fn torn_files(&self, stem: &str) -> io::Result<Vec<PathBuf>> {
        let prefix = format!("{stem}.torn-");
        let dir = self.run_dir(stem);
        let mut out = Vec::new();
        match std::fs::read_dir(&dir) {
            Ok(entries) => {
                for e in entries {
                    let e = e?;
                    if e.file_name().to_string_lossy().starts_with(&prefix) {
                        out.push(e.path());
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        Ok(out)
    }

    pub fn format_file(&self) -> PathBuf {
        self.data_dir.join("FORMAT")
    }

    pub fn server_lock(&self) -> PathBuf {
        self.data_dir.join("server.lock")
    }

    pub fn index_key(&self) -> PathBuf {
        self.data_dir.join("index.key")
    }

    pub fn anchors_dir(&self) -> PathBuf {
        self.data_dir.join("anchors")
    }

    pub fn audit_dir(&self) -> PathBuf {
        self.data_dir.join("audit")
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FormatFile {
    data_format: u32,
}

/// The data format recorded in `FORMAT`, or `None` when the file is
/// missing.
pub fn read_format(layout: &Layout) -> io::Result<Option<u32>> {
    Ok(fsutil::read_json::<FormatFile>(&layout.format_file())?.map(|f| f.data_format))
}

/// Record the data format.
pub fn write_format(layout: &Layout, format: u32) -> io::Result<()> {
    fsutil::write_json_atomic(
        &layout.format_file(),
        &FormatFile {
            data_format: format,
        },
    )
}

/// True if the directory holds nothing yet (or does not exist), apart from
/// the server lock.
pub fn is_fresh(dir: &Path) -> io::Result<bool> {
    match std::fs::read_dir(dir) {
        Ok(mut entries) => {
            Ok(entries.all(|e| e.map(|e| e.file_name() == "server.lock").unwrap_or(false)))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e),
    }
}

/// Check (or, for a fresh directory, write) `FORMAT`. The server refuses to
/// start on a format it does not know, or on a directory with data but no
/// `FORMAT` (run `migrate`).
pub fn check_format(layout: &Layout) -> Result<(), String> {
    match read_format(layout).map_err(|e| format!("FORMAT: {e}"))? {
        Some(DATA_FORMAT) => Ok(()),
        Some(other) => Err(format!(
            "data format {other} is not supported by this build (it reads format {DATA_FORMAT}); \
             use the matching server version or run `pragmatic-server migrate`"
        )),
        None => {
            let fresh = is_fresh(&layout.data_dir).map_err(|e| format!("data_dir: {e}"))?;
            if fresh {
                fsutil::create_dir_durable(&layout.data_dir).map_err(|e| e.to_string())?;
                write_format(layout, DATA_FORMAT).map_err(|e| format!("FORMAT: {e}"))
            } else {
                Err("the data directory has no FORMAT file; run `pragmatic-server migrate`".into())
            }
        }
    }
}

/// The subjects index key: read it, or create it in a fresh directory.
pub fn index_key(layout: &Layout) -> io::Result<[u8; 32]> {
    let path = layout.index_key();
    match std::fs::read(&path) {
        Ok(bytes) => bytes
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "index.key is not 32 bytes")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut key = [0u8; 32];
            pragmatic::rand::fill(&mut key)?;
            fsutil::write_new_private(&path, &key)?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsutil::testdir::TestDir;

    #[test]
    fn names_are_hashed_and_sharded() {
        let l = Layout::new("/d");
        let s = stem("run-1");
        assert!(is_stem(&s));
        assert_eq!(
            l.journal(&s),
            PathBuf::from(format!("/d/runs/{}/{s}.journal", &s[..2]))
        );
        assert!(l.meta(&s).to_string_lossy().ends_with(".meta.json"));
    }

    #[test]
    fn format_is_written_fresh_and_refused_when_unknown() {
        let d = TestDir::new("format");
        let l = Layout::new(d.join("data"));
        check_format(&l).unwrap();
        assert_eq!(read_format(&l).unwrap(), Some(DATA_FORMAT));
        write_format(&l, 99).unwrap();
        assert!(check_format(&l).unwrap_err().contains("99"));
        std::fs::remove_file(l.format_file()).unwrap();
        std::fs::write(l.data_dir.join("tokens.json"), "{}").unwrap();
        assert!(check_format(&l).unwrap_err().contains("migrate"));
    }

    #[test]
    fn the_index_key_persists() {
        let d = TestDir::new("ikey");
        let l = Layout::new(&*d);
        let a = index_key(&l).unwrap();
        assert_eq!(index_key(&l).unwrap(), a);
    }
}
