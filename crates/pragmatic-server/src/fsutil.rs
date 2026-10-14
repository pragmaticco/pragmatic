//! Durable file operations (design 4.2).
//!
//! Every JSON file the server owns is replaced atomically: written to a
//! temp file in the same directory, fsynced, renamed over the old file,
//! and then the directory is fsynced so the rename itself survives a
//! crash. A reader therefore sees either the old file or the new one,
//! never a mix, and a crash never leaves a half-written `meta.json`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::de::DeserializeOwned;
use serde::Serialize;

/// Make the directory entry changes in `dir` (creations, renames) durable.
pub fn fsync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        // Windows has no directory fsync; MoveFileEx with write-through
        // (what std's rename uses) is the closest equivalent.
        let _ = dir;
        Ok(())
    }
}

/// A temp path next to `path`, unique within this process.
pub fn temp_path(path: &Path) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.tmp-{}-{n}", std::process::id()))
}

/// Replace `path` with `bytes` atomically and durably.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let temp = temp_path(path);
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&temp, path)?;
        fsync_dir(dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Serialize `value` as pretty JSON and replace `path` with it atomically.
pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    write_atomic(path, &bytes)
}

/// Read a JSON file; `Ok(None)` if it does not exist.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Create `dir` and its parents, fsyncing the parent of each directory
/// created so the new entries are durable.
pub fn create_dir_durable(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        if !parent.as_os_str().is_empty() {
            create_dir_durable(parent)?;
        }
    }
    match fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(e) => return Err(e),
    }
    if let Some(parent) = dir.parent() {
        if !parent.as_os_str().is_empty() {
            fsync_dir(parent)?;
        }
    }
    Ok(())
}

/// Write all of `buf` at `offset`.
pub fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.write_all_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let (mut buf, mut offset) = (buf, offset);
        while !buf.is_empty() {
            match file.seek_write(buf, offset) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    buf = &buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Read exactly `buf.len()` bytes at `offset`.
pub fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let (mut buf, mut offset) = (buf, offset);
        while !buf.is_empty() {
            match file.seek_read(buf, offset) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Read the first `len` bytes of an open file.
pub fn read_prefix(file: &File, len: u64) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len as usize];
    read_exact_at(file, &mut buf, 0)?;
    Ok(buf)
}

/// Take an exclusive lock on `path` (created if missing) without waiting.
/// `Ok(None)` if another process or handle holds it. The lock lasts as long
/// as the returned file stays open.
pub fn try_lock_exclusive(path: &Path) -> io::Result<Option<File>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(fs::TryLockError::Error(e)) => Err(e),
    }
}

/// Write a new file that must not exist yet, readable only by its owner,
/// and fsync it and its directory.
pub fn write_new_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fsync_dir(path.parent().unwrap_or(Path::new(".")))
}

#[cfg(test)]
pub(crate) mod testdir {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A fresh empty directory, removed on drop.
    pub struct TestDir(PathBuf);

    impl TestDir {
        pub fn new(name: &str) -> TestDir {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!(
                "pragmatic-server-unit-{name}-{}-{n}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            TestDir(p)
        }
    }

    impl std::ops::Deref for TestDir {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testdir::TestDir;
    use super::*;

    #[test]
    fn atomic_writes_replace_whole_files() {
        let d = TestDir::new("atomic");
        let p = d.join("x.json");
        write_json_atomic(&p, &serde_json::json!({"a": 1})).unwrap();
        write_json_atomic(&p, &serde_json::json!({"a": 2})).unwrap();
        let v: serde_json::Value = read_json(&p).unwrap().unwrap();
        assert_eq!(v["a"], 2);
        let leftovers: Vec<_> = fs::read_dir(&*d)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
        assert!(read_json::<serde_json::Value>(&d.join("missing.json"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn exclusive_locks_exclude() {
        let d = TestDir::new("lock");
        let p = d.join("server.lock");
        let held = try_lock_exclusive(&p).unwrap().expect("first lock");
        assert!(try_lock_exclusive(&p).unwrap().is_none());
        drop(held);
        assert!(try_lock_exclusive(&p).unwrap().is_some());
    }

    #[test]
    fn positioned_io() {
        let d = TestDir::new("pio");
        let p = d.join("f");
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&p)
            .unwrap();
        write_all_at(&f, b"hello", 0).unwrap();
        write_all_at(&f, b" world", 5).unwrap();
        assert_eq!(read_prefix(&f, 11).unwrap(), b"hello world");
        let mut buf = [0u8; 5];
        read_exact_at(&f, &mut buf, 6).unwrap();
        assert_eq!(&buf, b"world");
        create_dir_durable(&d.join("a/b/c")).unwrap();
        assert!(d.join("a/b/c").is_dir());
        write_new_private(&d.join("a/key"), b"k").unwrap();
        assert!(write_new_private(&d.join("a/key"), b"k").is_err());
    }
}
